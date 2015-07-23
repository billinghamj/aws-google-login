const express = require('express');
const Q = require('q');
const GoogleAuth = require('google-auth-library');
const AWS = require('aws-sdk');
const JsonClient = require('json-client');
const url = require('url');

// env
const AwsRole = process.env.AWS_ROLE;
const GoogleAppId = process.env.GOOGLE_APP_ID;
const GoogleAppSecret = process.env.GOOGLE_APP_SECRET;
const GoogleDomain = process.env.GOOGLE_DOMAIN;
const BaseURL = process.env.BASE_URL;

const RedirectURL = url.resolve(BaseURL, 'auth');

// api clients
const google = new GoogleAuth();
const oauth2 = new google.OAuth2(GoogleAppId, GoogleAppSecret, RedirectURL);
const sts = new AWS.STS();
const federation = JsonClient('https://signin.aws.amazon.com/');

// express app
const app = express();

app.get('/', wrap(initiateLogin));
app.get('/auth', wrap(receiveToken));

const port = process.env.PORT || 3000;
app.listen(port, () => console.info('listening on port ' + port));

// convenience async wrap
function wrap(handler) {
	return function (req, res) {
		handler(req, res)
		.catch(function (err) {
			console.warn(err.stack);
			res.status(401);
			res.send('not authenticated');
		});
	};
}

// first request, redirects to authorization
async function initiateLogin(req, res) {
	const url = oauth2.generateAuthUrl({
		scope: ['email', 'profile', 'openid'],
		hd: GoogleDomain
	});

	res.redirect(url);
}

// after authorization, redirects to aws console
async function receiveToken(req, res) {
	const result = await Q.ninvoke(oauth2, 'getToken', req.query.code);
	const idt = result[0].id_token;

	const login = await Q.ninvoke(oauth2, 'verifyIdToken', idt, GoogleAppId);
	const payload = login.getPayload();

	if (payload.hd !== GoogleDomain)
		throw new Error('wrong domain');

	const cred = await Q.ninvoke(sts, 'assumeRoleWithWebIdentity', {
		RoleArn: AwsRole,
		RoleSessionName: payload.email,
		WebIdentityToken: idt,
		DurationSeconds: 3600
	});

	const token = await federation('get', 'federation', {
		Action: 'getSigninToken',
		Session: JSON.stringify({
			sessionId: cred.Credentials.AccessKeyId,
			sessionKey: cred.Credentials.SecretAccessKey,
			sessionToken: cred.Credentials.SessionToken
		})
	});

	let url = 'https://signin.aws.amazon.com/federation?Action=login';
	url += '&Issuer=' + encodeURIComponent(BaseURL);
	url += '&Destination=' + encodeURIComponent('https://console.aws.amazon.com');
	url += '&SigninToken=' + encodeURIComponent(token.SigninToken);

	res.redirect(url);
}
