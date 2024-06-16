import csv
from flask import Flask, request
import pickle
import pandas as pd
import validators
from extract_features import extractFeatures
from flask_cors import CORS

app = Flask('app')
CORS(app)

@app.route('/predict', methods=['POST'])
def predict():
    url = request.form['url']
    url = url.strip()
    if not validators.url(url):
        return 'Invalid URL'
    if len(url) > 2048:
        return 'URL is too long'
    features = extractFeatures(url)
    with open('model.bin','rb') as file:
        model = pickle.load(file)
        file.close()
    d = [[]]
    d.append(list(features))
    d.pop(0)
    df = pd.DataFrame(list(d))
    pred = model.predict(df)
    if pred[0] == 1:
        return 'Phishing Website'
    else:
        return 'Not a Phishing Website'

@app.route('/updateDataset', methods=['POST'])
def updateDataset():
    url = request.form['url']
    url = url.strip()
    if not validators.url(url):
        return 'Invalid URL'
    if len(url) > 2048:
        return 'URL is too long'
    features = extractFeatures(url)
    features.append(1)
    with open('datasetUpdate.csv','a',newline='') as f:
        wr = csv.writer(f, dialect='excel')
        wr.writerow(features)
        f.close()
    return 'Update Success'

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=9696)

