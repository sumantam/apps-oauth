const _ = require('lodash');
const path = require('path');
const express = require('express');
const hubspot = require('@hubspot/api-client');
const bodyParser = require('body-parser');
//const fetch = require('node-fetch'); // Import fetch for Node.js
const fetch = global.fetch || require('node-fetch');
require('./config');

const PORT = 3000;
const OBJECTS_LIMIT = 30;
const CLIENT_ID = process.env.HUBSPOT_CLIENT_ID;
const CLIENT_SECRET = process.env.HUBSPOT_CLIENT_SECRET;
const SCOPES = 'crm.objects.contacts.read';
const REDIRECT_URI = `http://localhost:${PORT}/oauth-callback`;
const GRANT_TYPES = {
  AUTHORIZATION_CODE: 'authorization_code',
  REFRESH_TOKEN: 'refresh_token',
};

let tokenStore = {};

const logResponse = (message, data) => {
  console.log(message, JSON.stringify(data, null, 1));
};

const checkEnv = (req, res, next) => {
  if (_.startsWith(req.url, '/error')) return next();

  if (_.isNil(CLIENT_ID))
    return res.redirect(
      '/error?msg=Please set HUBSPOT_CLIENT_ID env variable to proceed'
    );
  if (_.isNil(CLIENT_SECRET))
    return res.redirect(
      '/error?msg=Please set HUBSPOT_CLIENT_SECRET env variable to proceed'
    );

  next();
};

const isAuthorized = () => {
  return !_.isEmpty(tokenStore.refreshToken);
};

const isTokenExpired = () => {
  return Date.now() >= tokenStore.updatedAt + tokenStore.expiresIn * 1000;
};

const prepareContactsContent = (contacts) => {
  return _.map(contacts, (contact) => {
    const companyName = _.get(contact, 'properties.company') || '';
    const name = getFullName(contact.properties);
    return { id: contact.id, name, companyName };
  });
};

const getFullName = (contactProperties) => {
  const firstName = _.get(contactProperties, 'firstname') || '';
  const lastName = _.get(contactProperties, 'lastname') || '';
  return `${firstName} ${lastName}`;
};

const refreshToken = async () => {
  const result = await hubspotClient.oauth.tokensApi.create(
    GRANT_TYPES.REFRESH_TOKEN,
    undefined,
    undefined,
    CLIENT_ID,
    CLIENT_SECRET,
    tokenStore.refreshToken
  );
  tokenStore = result;
  tokenStore.updatedAt = Date.now();
  console.log('Updated tokens', tokenStore);

  hubspotClient.setAccessToken(tokenStore.accessToken);
};

const handleError = (e, res) => {
  if (_.isEqual(e.message, 'HTTP request failed')) {
    const errorMessage = JSON.stringify(e, null, 2);
    console.error(errorMessage);
    return res.redirect(`/error?msg=${errorMessage}`);
  }

  console.error(e);
  res.redirect(
    `/error?msg=${JSON.stringify(e, Object.getOwnPropertyNames(e), 2)}`
  );
};

const app = express();

const hubspotClient = new hubspot.Client();

app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'pug');
app.set('views', path.join(__dirname, 'views'));

app.use(
  bodyParser.urlencoded({
    limit: '50mb',
    extended: true,
  })
);

app.use(
  bodyParser.json({
    limit: '50mb',
    extended: true,
  })
);

app.use(checkEnv);

app.get('/', async (req, res) => {
  try {
    if (!isAuthorized()) return res.redirect('/login');
    if (isTokenExpired()) await refreshToken();

    const properties = ['firstname', 'lastname', 'company'];

    // Get first contacts page
    // GET /crm/v3/objects/contacts
    // https://developers.hubspot.com/docs/api/crm/contacts
    console.log('Calling crm.contacts.basicApi.getPage. Retrieve contacts.');
    const contactsResponse = await hubspotClient.crm.contacts.basicApi.getPage(
      OBJECTS_LIMIT,
      undefined,
      properties
    );
    logResponse('Response from API', contactsResponse);

    res.render('contacts', {
      tokenStore,
      contacts: prepareContactsContent(contactsResponse.results),
    });
  } catch (e) {
    handleError(e, res);
  }
});

app.use('/oauth', async (req, res) => {
  // Use the client to get authorization Url
  // https://www.npmjs.com/package/@hubspot/api-client#obtain-your-authorization-url
  console.log('Creating authorization Url');
  const authorizationUrl = hubspotClient.oauth.getAuthorizationUrl(
    CLIENT_ID,
    REDIRECT_URI,
    SCOPES
  );
  console.log('Authorization Url', authorizationUrl);

  res.redirect(authorizationUrl);
});

app.use('/oauth-callback', async (req, res) => {
  const code = _.get(req, 'query.code');

  // Create OAuth 2.0 Access Token and Refresh Tokens
  // POST /oauth/v1/token
  // https://developers.hubspot.com/docs/api/working-with-oauth
  console.log('Retrieving access token by code:', code);
  const getTokensResponse = await hubspotClient.oauth.tokensApi.create(
    GRANT_TYPES.AUTHORIZATION_CODE,
    code,
    REDIRECT_URI,
    CLIENT_ID,
    CLIENT_SECRET
  );
  logResponse('Retrieving access token result:', getTokensResponse);

  tokenStore = getTokensResponse;
  tokenStore.updatedAt = Date.now();

  // Set token for the
  // https://www.npmjs.com/package/@hubspot/api-client
  hubspotClient.setAccessToken(tokenStore.accessToken);
  res.redirect('/');
});

app.get('/login', (req, res) => {
  tokenStore = {};
  res.render('login', { redirectUri: REDIRECT_URI });
});

app.get('/refresh', async (req, res) => {
  try {
    if (isAuthorized()) await refreshToken();
    res.redirect('/');
  } catch (e) {
    handleError(e, res);
  }
});

app.get('/error', (req, res) => {
  res.render('error', { error: req.query.msg });
});

/*
app.use((error, req, res) => {
  res.render('error', { error: error.message });
});

*/

app.use((error, req, res, next) => {
  res.status(500).render('error', { error: error.message });
});


async function trackShipment() {
    try {
	const UPS_API_URL = `https://wwwcie.ups.com/api/track/v1/details/1234578?locale=en_US&returnSignature=false&returnMilestones=false&returnPOD=false`
        const response = await fetch(UPS_API_URL, {
            method: 'GET',
            headers: {
		transId: 'testing',
                transactionSrc: 'testing',
                'Content-Type': 'application/json',
		Authorization: `Bearer eyJraWQiOiI5NzllNmVhYy1iZmExLTQzZmQtYTliZi05NTBhYzE0OGVkNjMiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9.eyJzdWIiOiJzcml5YS5tYWlsQGdtYWlsLmNvbSIsImNsaWVudGlkIjoiNm5jRnhoSlFuRXFiaVdXaVkyT0FOUEdYSmVpdERtc2R6WFpkcHlGS1BtRlFjWW1EIiwiaXNzIjoiaHR0cHM6Ly9hcGlzLnVwcy5jb20iLCJ1dWlkIjoiMjdENDYyMDItNzUwMC0xMDgyLTlDRTAtOEU2MTM1OTMxQ0MzIiwic2lkIjoiOTc5ZTZlYWMtYmZhMS00M2ZkLWE5YmYtOTUwYWMxNDhlZDYzIiwiYXVkIjoiSHVic3BvdCBVUFMgVHJhY2tpbmcgQXBwIiwiYXQiOiJHY0FrN3RXNGF5ZGxyVFlpdlMzTDlSZ1VWOEp1IiwibmJmIjoxNzQyODI5OTcwLCJEaXNwbGF5TmFtZSI6Ikh1YnNwb3QgVVBTIFRyYWNraW5nIEFwcCIsImV4cCI6MTc0Mjg0NDM3MCwiaWF0IjoxNzQyODI5OTcwLCJqdGkiOiI5NGJlY2JmMC03MjkzLTQwNzMtYTRiNi01ZWUyZWNhNWRkMzMifQ.PR0NqLI_WzpsK6Uu7kNXPNczZp9O43ed79IlvDmtwWZhRoLDM5RDTt9FiaPVWP_Kda4HSP6fu0v_xK-WhmLLxN8ga7_dh7eExwsArVYog9TjgzjE2a8sISwWKHPHL3fHtDKbkZ17VpIO-Yj_06JT0P9Iac1iLxwXTeu6ifbgO831i4_IgxiW6t9P8wWChK9K7sx_ZGkYgZcCbge-34nZFez6gyYiWeYmHCvlZDAUo7d9EKZDym7WUuR7AlZwtq87fpJ9J1eRndjg0EYfh2DerI2-bSTo1zuieFoE0CamqhiiF1DSGtuB7DWLejhlQV-uSqK-fouM9X0McQZksGBHH1ACjFQw8N0sTQWdBNf8yi0WHSIu9TG_9BFgknmy3jdnW0_hjdwTMHkBeKwd9hCwm8WTxXTY4jLSCdZd_3q9ZUPQTvWwwFsWSmPMBq6jUzahtf-mgJpVq6dv6xHrUbqA3wjwDOOchcjaLZuLFK0-pWprFPcA0fwW4E4SHUOmgmWqrbD4-i05poNCNsUGUMUJOMg3-Wet7j_X44OuCkAspugtqkrMTmXY5TmEZGfaV7gpg3Adu6KbhE7MlU4MbRbmP3E4MeZzrEXYiFjjfHyKKDHr54XLm5oRq5uF1-BdEajXsM37Ra-uomJQSLtj5oxj6EqwxBHnEditjr8GhURWF6E`

            }
        });

        if (!response.ok) {
            throw new Error(`UPS API responded with status ${response.status}`);
        }

        const data = await response.json();
        console.log('UPS Tracking Data:', data);
        return data; // ✅ Return tracking data
    } catch (error) {
        console.error('Error fetching UPS tracking data:', error.message);
	throw error;
    }
}


app.get('/tracking', async (req, res) => {
  try {
/*    
    if (!isAuthorized()) return res.redirect('/login');
    if (isTokenExpired()) await refreshToken();
*/
    console.log('Calling ups tracking');
    // Run the function
    const data = await trackShipment();
    res.json({ status: 'success', trackingData: data });
  } catch (e) {
    handleError(e, res);
  }

});

app.listen(PORT, () => console.log(`Listening on http://localhost:${PORT}`));
