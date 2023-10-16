import json
import string
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify 
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import requests
import hashlib

app = Flask(__name__)
app.secret_key = 'votre_clé_secrète_ici'

# Création d'une clé de chiffrement et initialisation de la suite de chiffrement
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Hash du mot de passe maître pour vérification
MASTER_PASSWORD_HASH = generate_password_hash("")

@app.route('/')
def login():
    return render_template('login.html')

@app.route('/check_login', methods=['POST'])
def check_login():
    password = request.form.get('password')
    if check_password_hash(MASTER_PASSWORD_HASH, password):
        session['logged_in'] = True
        return redirect(url_for('dashboard'))  
    flash('Mot de passe incorrect', 'danger')
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if request.method == 'POST':
        nom = request.form.get('nom')
        login = request.form.get('login')
        mot_de_passe = request.form.get('mot_de_passe')

        # Ajoutez les données au fichier JSON
        with open('data.json', 'r') as f:
            data = json.load(f)

        data['sites'].append({
            'nom': nom,
            'login': login,
            'mot_de_passe': mot_de_passe
        })

        with open('data.json', 'w') as f:
            json.dump(data, f)

    # Charger les données du fichier JSON pour l'affichage
    with open('data.json', 'r') as f:
        data = json.load(f)

    # Calculer la force du mot de passe pour chaque site
    for site in data["sites"]:
        site['password_length'] = len(site['mot_de_passe'])
        strength_score = evaluate_password_strength(site['mot_de_passe'])
        description = password_descriptions[strength_score]
        site['strength'] = {
            'description': description,
            'color': password_colors[description]
        }
        
        # Vérifiez si le mot de passe a été compromis en ligne
        is_leaked = check_password_leak(site['mot_de_passe'])
        site['leaked_online'] = 'OUI' if is_leaked else 'NON'

    return render_template('dashboard.html', data=data)






def check_password_leak(password):
    # Calculer le hash SHA-1 complet du mot de passe
    sha1_full_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    
    # Extraire les cinq premiers caractères du hash pour la requête
    sha1_prefix = sha1_full_hash[:6]

    # Faites une requête à l'API "Have I Been Pwned" pour vérifier si le hash existe dans les fuites
    response = requests.get(f'https://api.pwnedpasswords.com/range/{sha1_prefix}')
    
    if response.status_code == 200:
        # Analysez la réponse pour voir si le hash complet correspond à l'un des retours de l'API
        hashes = [line.split(':') for line in response.text.splitlines()]
        for h, count in hashes:
            if sha1_full_hash[6:] == h:  # Comparer seulement le suffixe du hash complet
                return True  # Le mot de passe a été compromis
    return False  # Le mot de passe n'a pas été compromis

# Test de la fonction
password = "your_password_here"
if check_password_leak(password):
    print("Le mot de passe a été compromis!")
else:
    print("Petit souci.")



password_descriptions = {
    1: "Très faible",
    2: "Faible",
    3: "Moyen",
    4: "Fort",
    5: "Très fort"
}


def password_strength(password):
    length = len(password.encode('utf-8'))  
    if length < 15:
        return 'faible', 'darkred'
    elif length < 21:
        return 'moyen', 'orange'
    elif length < 40:
        return 'bon', 'green'
    else:
        return 'très bon', 'darkgreen'


password_colors = {
    "Très faible": "red",
    "Faible": "orange",
    "Fort": "lightgreen",
    "Très fort": "green",
    "Extrêmement fort": "darkgreen"
}


def evaluate_password_strength(password):
    """
    Évalue la solidité d'un mot de passe basé sur certains critères.
    
    Retourne un score compris entre 0 et 5, où 5 indique un mot de passe très fort.
    """
    score = 0

    # Longueur du mot de passe
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1

    # Lettres majuscules et minuscules
    if any(char in string.ascii_lowercase for char in password):
        score += 1
    if any(char in string.ascii_uppercase for char in password):
        score += 1

    # Présence de chiffres
    if any(char.isdigit() for char in password):
        score += 1

    # Présence de caractères spéciaux
    special_characters = string.punctuation
    if any(char in special_characters for char in password):
        score += 1

    # Assurez-vous que le score est compris entre 0 et 5
    return min(score, 5)





@app.route('/dashboard/delete/<int:index>', methods=['DELETE'])
def delete_site(index):
    # Charger les données du fichier JSON
    with open('data.json', 'r') as f:
        data = json.load(f)

    try:
        # Supprimer l'élément à l'index spécifié
        deleted_site = data['sites'].pop(index - 1)
        with open('data.json', 'w') as f:
            json.dump(data, f)

        return jsonify({'success': True, 'message': f'Élément "{deleted_site["nom"]}" supprimé avec succès.'})
    except IndexError:
        return jsonify({'success': False, 'message': 'Index de l\'élément à supprimer non valide.'})


@app.route('/dashboard/edit', methods=['GET', 'POST'])
def edit_site():
    # Chargez les données du fichier JSON dès le début de la fonction
    with open('data.json', 'r') as f:
        data = json.load(f)

    if request.method == 'POST':
        index = int(request.form.get('index'))
        if 0 <= index < len(data['sites']):
            nom = request.form.get('nom')
            login = request.form.get('login')
            mot_de_passe = request.form.get('mot_de_passe')
            
            data['sites'][index] = {
                'nom': nom,
                'login': login,
                'mot_de_passe': mot_de_passe
                # Ajoutez d'autres champs si nécessaire
            }
            
            with open('data.json', 'w') as f:
                json.dump(data, f)
            
            return redirect(url_for('dashboard'))
        else:
            return jsonify({'Index de l\'élément à modifier non valide.'})
    else:
        index = request.args.get('index')
        site = data['sites'][int(index)]
        
        return render_template('dashboard.html', site=site, index=index)




if __name__ == '__main__':
    app.run(debug=True, port=4254)
