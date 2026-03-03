## Look for a file called "security_breach.txt" in your computer. How was it created?

Le fichier se créer à l'execution du fichier transformers.py en créant le dossier tmp puis le fichier security_breach.txt


## This file created is quite harmless; could you give an example of something that could have been done more harmful?

Le fichier aurait pu supprimer des fichiers système, voler des mots de passes où encore installer des malware


## Implement a new way to safely share models (hint: check the library skops)

La librairie skops permet d'inspecter un modèle avant de le charger, charge uniquement des types approuvés et empêche l'exécution de code arbitraire.