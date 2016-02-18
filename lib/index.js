var util = require('util');
var uri = require('url');
var OAuth2Strategy = require('passport-oauth2');
var InternalOAuthError = require('passport-oauth2').InternalOAuthError;

util.inherits(KakaoTokenStrategy, OAuth2Strategy);

/**
 * `KakaoTokenStrategy` constructor.
 *
 * The Kakao authentication strategy authenticates requests by delegating to
 * Kakao using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occurred, `error` should be set.
 *
 * Options:
 *   - `clientID`      your Kakao application's App Key
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function KakaoTokenStrategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://kauth.kakao.com/oauth/authorize';
  options.tokenURL = options.tokenURL || 'https://kauth.kakao.com/oauth/token';
  options.scopeSeparator = options.scopeSeparator || ',';
  options.clientSecret = 'kakao';

  OAuth2Strategy.call(this, options, verify);

  this.name = 'kakao-token';
  this._accessTokenField = options.accessTokenField || 'access_token';
  this._refreshTokenField = options.refreshTokenField || 'refresh_token';
  this._passReqToCallback = options.passReqToCallback;
  this._profileURL = options.profileURL || 'https://kapi.kakao.com/v1/user/me';
  delete this._oauth2._clientSecret;
}

/**
 * Authenticate request by delegating to a service provider using OAuth 2.0.
 * @param {Object} req
 * @param {Object} options
 * @api protected
 */
KakaoTokenStrategy.prototype.authenticate = function (req, options) {
  var self = this;
  var accessToken = (req.body && req.body[self._accessTokenField]) || (req.query && req.query[self._accessTokenField]) || (req.headers && req.headers[self._accessTokenField]);
  var refreshToken = (req.body && req.body[self._refreshTokenField]) || (req.query && req.query[self._refreshTokenField]) || (req.headers && req.headers[self._refreshTokenField]);

  if (!accessToken) {
    return this.fail({
      message: 'You should provide access_token'
    });
  }

  self._loadUserProfile(accessToken, function (error, profile) {
    if (error) return self.error(error);

    function verified(error, user, info) {
      if (error) return self.error(error);
      if (!user) return self.fail(info);

      return self.success(user, info);
    }

    if (self._passReqToCallback) {
      self._verify(req, accessToken, refreshToken, profile, verified);
    } else {
      self._verify(accessToken, refreshToken, profile, verified);
    }
  });
};

/**
 * Retrieve user profile from Kakao.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `kakao`
 *   - `id`               the user's Kakao ID
 *   - `displayName`      the user's Kakao nickname
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
KakaoTokenStrategy.prototype.userProfile = function (accessToken, done) {
  var url = uri.parse(this._profileURL);

  url = uri.format(url);

  this._oauth2.get(url, accessToken, function (error, body, res) {
    if (error) return done(new InternalOAuthError('Failed to fetch user profile', error));

    try {
      var json = JSON.parse(body),
        profile = {
          provider: 'kakao',
          id: json.id,
          displayName: json.properties.nickname || '',
          photos: [{
            value: json.properties.profile_image
          }],
          _raw: body,
          _json: json
        };

      done(null, profile);
    } catch (e) {
      done(e);
    }
  });
}

/**
 * Expose `KakaoTokenStrategy`.
 */
module.exports = KakaoTokenStrategy;
module.exports.Strategy = KakaoTokenStrategy;
