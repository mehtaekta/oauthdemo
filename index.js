var express = require('express'),
	OAuth = require('oauth').OAuth,
	config = require('./config'),
	querystring = require('querystring');

app = module.exports = express.createServer();
app.configure(function(){
	// # Register view engine
	app.register('.html', require('ejs'))

	// # App Configuration
	app.set('views', __dirname + "/public")
	app.set('view engine', 'html')
	app.set('view options', { layout: false, pretty: true })

	// # Middleware
	app.use(express.static(__dirname + '/public'))
	app.use(express.bodyParser())
	app.use(express.cookieParser());
	app.use(express.session({
		secret: "skjghskdjfhbqigohqdiouk"
	}))
	
});

// Home Page
app.get('/', function(req, res){
	console.log('req.session.oauth_access_token', req.session.oauth_access_token);
	// console.log('oauth_access_token_secret', oauth_access_token_secret);
	if(!req.session.oauth_access_token) {
		res.redirect("/login");
	}
	else {
		next();
		// res.redirect("/google_contacts");
	}
});

app.get('/home', function(req, res){
	console.log('req.session.oauth_access_token', req.session.oauth_access_token);
	// console.log('oauth_access_token_secret', oauth_access_token_secret);
	res.render('home.html', {});
});

// Request an OAuth Request Token, and redirects the user to authorize it
app.get('/login', function(req, res) {
	console.log('req.param("action")',req.param('action'));
	// GData specifid: scopes that wa want access to
	var gdataScopes = [
		querystring.escape("https://www.google.com/m8/feeds/"),
		querystring.escape("https://www.google.com/calendar/feeds/")
	];

	//exports.OAuth= function(requestUrl, accessUrl, consumerKey, consumerSecret, version,
	// authorize_callback, signatureMethod, nonceSize, customHeaders)
	var oa = new OAuth(config.google.requestTokenUrl+"?scope="+gdataScopes.join('+'),
	                  config.google.oAuthGetAccessToken,
	                  config.google.clientId,
	                  config.google.clientSecret,
	                  "1.0",
	                  "http://localhost:5000/google_cb"+( req.param('action') && req.param('action') != "" ? "?action="+querystring.escape(req.param('action')) : "" ),
	                  "HMAC-SHA1");

	oa.getOAuthRequestToken(function(error, oauth_token, oauth_token_secret, results){
	  if(error) {
			console.log('error');
	 		console.log(error);
		}
	  else { 
			// store the tokens in the session
			req.session.oa = oa;
			req.session.oauth_token = oauth_token;
			req.session.oauth_token_secret = oauth_token_secret;

			// redirect the user to authorize the token
	   		res.redirect(config.google.oAuthAuthorizeTokenUrl + "?oauth_token="+oauth_token);
	  }
	})

});

// Callback for the authorization page
app.get('/google_cb', function(req, res) {

	// get the OAuth access token with the 'oauth_verifier' that we received

	var oa = new OAuth(req.session.oa._requestUrl,
	                  req.session.oa._accessUrl,
	                  req.session.oa._consumerKey,
	                  req.session.oa._consumerSecret,
	                  req.session.oa._version,
	                  req.session.oa._authorize_callback,
	                  req.session.oa._signatureMethod);

    // console.log(oa);

	oa.getOAuthAccessToken(
		req.session.oauth_token, 
		req.session.oauth_token_secret, 
		req.param('oauth_verifier'), 
		function(error, oauth_access_token, oauth_access_token_secret, results2) {

			if(error) {
				console.log('error');
				console.log(error);
	 		}
	 		else {

				// store the access token in the session
				req.session.oauth_access_token = oauth_access_token;
				req.session.oauth_access_token_secret = oauth_access_token_secret;

	    		res.redirect((req.param('action') && req.param('action') != "") ? req.param('action') : "/home");
	 		}

	});

});



port = process.env.PORT || 5000
app.listen(port)
console.log("Express server listening on port %d in %s mode", port, app.settings.env)