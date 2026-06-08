#!/usr/bin/env python3
"""
Alerte mail Wazuh + Ollama (a lancer par cron)
----------------------------------------------
Interroge l'indexeur Wazuh pour les alertes de severite >= seuil sur
une fenetre de temps. S'il y en a, fait rediger une analyse par Ollama
et envoie un mail contenant l'analyse IA ET la liste des evenements
bruts. S'il n'y a rien, n'envoie aucun mail.

La detection de severite repose sur le NIVEAU DE REGLE (deterministe).
L'IA ne sert qu'a rediger le corps du mail.

Dependances : requests (smtplib / email sont dans la lib standard)
"""

import smtplib
from email.message import EmailMessage

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===========================================================================
# CONFIGURATION
# ===========================================================================
# --- Indexeur Wazuh ---
OPENSEARCH_URL  = "https://192.168.2.50:9200"
OPENSEARCH_USER = "admin"
OPENSEARCH_PASS = "TON_MDP"
INDEX           = "wazuh-alerts-*"
VERIFY_SSL      = False
TIME_FIELD      = "timestamp"

# --- Seuil et fenetre ---
LEVEL_THRESHOLD = 7        # alerte si rule.level >= 7
LOOKBACK_HOURS  = 1        # IMPORTANT : faire correspondre a la frequence du cron
                           # (cron horaire -> 1 ; toutes les 4h -> 4) pour ne pas
                           # re-alerter sur les memes evenements
MAX_EVENTS      = 50       # nombre max d'evenements bruts listes dans le mail

# --- Ollama ---
OLLAMA_URL      = "http://localhost:11434/api/generate"
OLLAMA_MODEL    = "llama3:8b"

# --- SMTP (envoi du mail) ---
SMTP_SERVER = "smtp.dietagro.com"
SMTP_PORT   = 587
SMTP_TLS    = True
SMTP_USER   = ""                       # vide si relais interne sans authentification
SMTP_PASS   = ""
SMTP_FROM   = ""
SMTP_TO     = ""       # plusieurs destinataires : "a@x.fr, b@x.fr"

# ===========================================================================
# 1. Recuperation des alertes de severite elevee
# ===========================================================================
def fetch_alerts():
    query = {
        "size": MAX_EVENTS,
        "sort": [{TIME_FIELD: {"order": "desc"}}],
        "query": {
            "bool": {
                "filter": [
                    {"range": {TIME_FIELD: {"gte": f"now-{LOOKBACK_HOURS}h"}}},
                    {"range": {"rule.level": {"gte": LEVEL_THRESHOLD}}},
                ]
            }
        },
        "aggs": {
            "par_regle":  {"terms": {"field": "rule.id",    "size": 15}},
            "par_agent":  {"terms": {"field": "agent.name", "size": 15}},
            "par_niveau": {"terms": {"field": "rule.level", "size": 15}},
        },
    }
    r = requests.get(
        f"{OPENSEARCH_URL}/{INDEX}/_search",
        json=query, auth=(OPENSEARCH_USER, OPENSEARCH_PASS),
        verify=VERIFY_SSL, timeout=30,
    )
    if not r.ok:
        print("REPONSE INDEXEUR:", r.text)
    r.raise_for_status()
    return r.json()


def total_hits(resp):
    t = resp.get("hits", {}).get("total", 0)
    return t.get("value", 0) if isinstance(t, dict) else t


# ===========================================================================
# 2. Synthese agregee (pour l'IA) et liste brute (pour le mail)
# ===========================================================================
def build_summary(resp):
    aggs = resp.get("aggregations", {})
    out = [f"Nombre total d'alertes (niveau >= {LEVEL_THRESHOLD}) sur les "
           f"{LOOKBACK_HOURS} dernieres heures : {total_hits(resp)}", ""]

    out.append("Par regle :")
    out += [f"  - regle {b['key']} : {b['doc_count']}"
            for b in aggs.get("par_regle", {}).get("buckets", [])] or ["  (aucune)"]

    out.append("\nPar machine :")
    out += [f"  - {b['key']} : {b['doc_count']}"
            for b in aggs.get("par_agent", {}).get("buckets", [])] or ["  (aucune)"]

    out.append("\nPar niveau de severite :")
    out += [f"  - niveau {b['key']} : {b['doc_count']}"
            for b in aggs.get("par_niveau", {}).get("buckets", [])] or ["  (aucun)"]

    return "\n".join(out)


def build_raw_list(resp):
    lines = []
    for hit in resp.get("hits", {}).get("hits", []):
        s = hit.get("_source", {})
        rule = s.get("rule", {})
        agent = s.get("agent", {})
        lines.append(
            f"{s.get('timestamp', '?')} | {agent.get('name', '?')} | "
            f"niveau {rule.get('level', '?')} | regle {rule.get('id', '?')} | "
            f"{rule.get('description', '?')}"
        )
    return lines


# ===========================================================================
# 3. Analyse redigee par Ollama
# ===========================================================================
PROMPT = """Tu es analyste SOC. Voici la synthese des alertes Wazuh de severite elevee \
(niveau >= {seuil}) sur la derniere periode. Redige une courte analyse en francais.

Structure :
1. Resume en une ou deux phrases (nombre d'alertes, machines concernees).
2. Faits marquants (par regle, par machine), avec les chiffres exacts.
3. Recommandations concretes.

Regles : base-toi UNIQUEMENT sur les donnees fournies, n'invente aucun chiffre, \
aucune machine. Reste factuel et concis.

SYNTHESE :
{summary}
"""


def ask_ollama(summary):
    try:
        r = requests.post(
            OLLAMA_URL,
            json={"model": OLLAMA_MODEL,
                  "prompt": PROMPT.format(seuil=LEVEL_THRESHOLD, summary=summary),
                  "stream": False},
            timeout=300,
        )
        r.raise_for_status()
        return r.json().get("response", "(pas de reponse du modele)")
    except Exception as e:
        return f"(analyse IA indisponible : {e})"


# ===========================================================================
# 4. Envoi du mail
# ===========================================================================
def send_email(subject, body):
    payload = {
        "sender": {"name": SENDER_NAME, "email": SENDER_EMAIL},
        "to": [{"email": TO_EMAIL, "name": TO_NAME}],
        "subject": subject,
        "textContent": body,
    }
    headers = {
        "api-key": BREVO_API_KEY,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    r = requests.post("https://api.brevo.com/v3/smtp/email",
                      json=payload, headers=headers, timeout=30)
    if not r.ok:
        print("REPONSE BREVO:", r.status_code, r.text)
    r.raise_for_status()


# ===========================================================================
# Main
# ===========================================================================
def main():
    resp = fetch_alerts()
    if not total_hits(resp):
        return  # rien de grave -> pas de mail

    summary = build_summary(resp)
    raw     = build_raw_list(resp)
    analysis = ask_ollama(summary)

    body = (
        "=== ANALYSE (IA) ===\n\n"
        f"{analysis}\n\n"
        f"=== EVENEMENTS BRUTS (niveau >= {LEVEL_THRESHOLD}) ===\n\n"
        + "\n".join(raw)
    )
    subject = f"[Wazuh] {total_hits(resp)} alerte(s) de severite >= {LEVEL_THRESHOLD}"
    send_email(subject, body)
    print(subject, "-> mail envoye")


if __name__ == "__main__":
    main()
