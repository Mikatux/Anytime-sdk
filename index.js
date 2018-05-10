const querystring = require('querystring');
const axios = require('axios');
const NodeRSA = require('node-rsa');

const sandboxUrl = "https://ws-sandbox.anyti.me";
const prodUrl = "https://ws.anyti.me";

class Anytime {

    constructor(client_id, client_secret, username, password, rsaPrivateKey, isProd = false) {
        this.client_id = client_id;
        this.client_secret = client_secret;
        this.username = username;
        this.password = password;
        this.rsaKey = new NodeRSA(rsaPrivateKey, { signingScheme: 'sha1' });
        this.apiUrl = isProd ? prodUrl : sandboxUrl;
    }

    _generateHeaders() {
        let validationData = Date.now();
        let validationDataSigned = this.rsaKey.sign(validationData, 'base64');
        return {
            'X-Validation-Data': validationData,
            'X-Signed-Request': validationDataSigned,
        }
    };

    async _getToken() {
        const data = querystring.stringify({
            grant_type: 'password',
            client_id: this.client_id,
            client_secret: this.client_secret,
            username: this.username,
            password: this.password,
        });
        try {
            let response = await axios({
                method: 'post',
                url: `${this.apiUrl}/oauth/v2/token`,
                data,
                headers: this._generateHeaders()
            });
            this.access_token = response.data.body.access_token;
            return this.access_token;
        }
        catch (e) {
            throw { status: e.response.status, body: e.response.data };
        }
    };

    async _callApi(endpoint) {
        if (!this.access_token) {
            await this._getToken();
        }
        try {
            const response = await axios({
                method: 'get',
                url: `${this.apiUrl}/${endpoint}`,
                headers: {
                    ... this._generateHeaders(),
                    'Authorization': `Bearer ${this.access_token}`
                }
            });
            return response.data.body;
        }
        catch (e) {
            throw { status: e.response.status, body: e.response.data };
        }
    }
    async apiCheck() {
        const response = await this._callApi('v1.0/apicheck');
        return response;
    }
    async getAccounts() {
        const response = await this._callApi('v1.0/accounts');
        return response.accounts;
    };
    async getAccountCards(accId) {
        const response = await this._callApi(`v1.0/accounts/${accId}/cards`);
        return response.cards;
    };
}
module.exports = Anytime;