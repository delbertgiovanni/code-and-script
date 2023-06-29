from feature import FeatureExtraction
import requests as req
from sklearn import metrics
import pandas as pd
import numpy as np
import warnings
import pickle
import json
warnings.filterwarnings('ignore')

file = open("pickle/model.pkl","rb")
gbc = pickle.load(file)
file.close()

class phishing_scan:
    def ml_analysis(self, dns, result):
        obj = FeatureExtraction(dns)
        x = np.array(obj.getFeaturesList()).reshape(1,30) 

        y_pred =gbc.predict(x)[0]
        y_pro_phishing = gbc.predict_proba(x)[0,0]
        y_pro_non_phishing = gbc.predict_proba(x)[0,1]
        y_pro_phishing = y_pro_phishing * 100
        y_pro_non_phishing = y_pro_non_phishing * 100

        result["Malware Probability Percentage"] = "{:.2f}".format(y_pro_phishing) + " %"
        result["Safe Probability Percentage"] = "{:.2f}".format(y_pro_non_phishing) + " %"
        return result

    def ip_check_talos(self, dns, result):
        url = 'https://talosintelligence.com/cloud_intel/url_reputation?url=' + dns
        resp = req.get(url)

        if resp.status_code == 200:
            data = resp.json()
            reputation = data['reputation']
            
            aup_cat = reputation.get('aup_cat', [])
            threat_cats = reputation.get('threat_cat', [])
            malware_description = None
            
            if threat_cats != None:
                for threat_cat in threat_cats:
                    if threat_cat['threat_cat_mnemonic'] == 'mals':
                        malware_description = threat_cat['desc_long'][0]['text']
                        break

            aup_cat_mnemonic = aup_cat[0]['aup_cat_mnemonic'] if aup_cat else None
            desc_long_text = aup_cat[0]['desc_long'][0]['text'] if aup_cat else None

            ip_reputation = {
                "Talos Intelligence": {
                    "Threat Level": reputation['threat_level_mnemonic'],
                    "Threat Level ID": reputation['threat_level_id'],
                    "Reputation Score": reputation['reputation_score_x10'],
                    "AUP Category": aup_cat_mnemonic,
                    "General Description": desc_long_text,
                    "Malware Information": malware_description
                }
            }
            result.setdefault('IP reputation', {}).update(ip_reputation)

        else:
            ip_reputation = {"Talos Intelligence": None}
            result.setdefault('IP reputation', {}).update(ip_reputation)

        return result

    def run(self, domain):
        result = {}
        result["URL"] = domain
        results = self.ip_check_talos(domain, result)
        results["Malware Probability Percentage"] = None
        results["Safe Probability Percentage"] = None
        results = self.ml_analysis(domain, result)
        result = json.dumps(results)
        print(result)

scanner = phishing_scan()
scanner.run("https://a.google.com")