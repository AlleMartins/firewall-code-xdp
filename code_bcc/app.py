from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/json', methods=['POST'])
def receive_json():
    data = request.get_json()  # Prende l'input JSON dalla richiesta
    if data is None:
        return jsonify({"error": "No JSON received"}), 400
    
    print(data)  # Stampa il JSON ricevuto sul terminale
    
    # Salva il JSON ricevuto in un file chiamato output.txt in modalità append
    with open('output.txt', 'a') as f:
        f.write(str(data) + '\n')
    
    return jsonify({"message": "JSON received and saved"}), 200

if __name__ == '__main__':
    app.run(debug=True)
