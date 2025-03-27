from flask import Flask, request, jsonify
import joblib
import json

app = Flask(__name__)

model = joblib.load('modelo_entrenado.pkl')
vectorizer = joblib.load('vectorizador.pkl')


def extraer_y_preprocesar(solicitud):
    # Verificar si la solicitud tiene dos partes (encabezados y cuerpo)

    if '\n' in solicitud:
        headers, params = solicitud.split('\n', 1)
    else:
        headers = solicitud
        params = ''

    headers_dict = {}

    # Procesar encabezados para obtener solo los campos necesarios
    campos_necesarios = ['Content-Type', 'User-Agent', 'Cookie']
    for line in headers.split('\n'):
        if ': ' in line:
            key, value = line.split(': ', 1)
            if key.strip() in campos_necesarios:
                headers_dict[key.strip()] = value.strip()

    # Convertir parámetros a diccionario sin excluir nada
    params_dict = {}
    for item in params.split('&'):
        if '=' in item:
            key, value = item.split('=', 1)  # Solo dividir en el primer signo de igual
            params_dict[key] = value

    # Crear la variable con la estructura especificada
    resultado = {
        'headers': headers_dict,
        'params': json.dumps(params_dict)
    }

    return resultado


@app.route('/predecir', methods=['POST'])
def predecir():
    solicitud = request.data.decode('utf-8')
    data = extraer_y_preprocesar(solicitud)
    headers = data['headers']
    params = data['params']

    # Preprocesar y vectorizar la solicitud
    texto_preprocesado = json.dumps(headers).lower() + ' ' + params.lower()
    X_new = vectorizer.transform([texto_preprocesado])

    # Realizar la predicción
    prediccion = model.predict(X_new)[0]

    # Devolver la predicción
    return jsonify({'prediccion': 'Maliciosa' if prediccion == 1 else 'Legítima'})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
