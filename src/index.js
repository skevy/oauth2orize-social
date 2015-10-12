import {AuthorizationError} from 'oauth2orize';

export default (parseSocialRequest, verifySocialAccount) => {
  return (opts, issue) => {
    if (typeof opts === 'function') {
      issue = opts;
      opts = null;
    }

    if (typeof issue !== 'function') {
      throw new Error('OAuth 2.0 Twitter exchange middleware ' +
        'requires an issue function.');
    }

    opts = opts || {};

    var userProperty = opts.userProperty || 'user';
    var separators = opts.scopeSeparator || ' ';

    if (!Array.isArray(separators)) {
      separators = [ separators ];
    }

    return function social(req, res, next) {
      if (!req.body) {
        return next(new Error('Request body not parsed. ' +
          'Use bodyParser middleware.'));
      }

      // The `user` property of `req` holds the authenticated user. In the case
      // of the token end-point, this property will contain the OAuth 2.0 client.
      var client = req[userProperty];
      var scope = req.body.scope;

      const socialAuthData = parseSocialRequest(req, res);

      verifySocialAccount(socialAuthData, function (err, profile) {
        if (err) {
          return next(err);
        }

        if (scope) {
          for (var i = 0, len = separators.length; i < len; i++) {
            // Only separates on the first matching separator.
            // This allows for a sort of separator "priority"
            // (ie, favors spaces then fallback to commas).
            var separated = scope.split(separators[i]);

            if (separated.length > 1) {
              scope = separated;
              break;
            }
          }

          if (!Array.isArray(scope)) {
            scope = [ scope ];
          }
        }

        var issued = function (issueErr, accessToken, refreshToken, params) {
          if (issueErr) {
            return next(issueErr);
          }

          if (!accessToken) {
            return next(new AuthorizationError(
              'Permissions were not granted.', 'invalid_grant'));
          }

          var json = { 'access_token': accessToken };

          if (refreshToken) {
            json['refresh_token'] = refreshToken;
          }

          if (params) {
            json = {
              ...json,
              ...params
            };
          }

          json['token_type'] = json['token_type'] || 'bearer';
          json = JSON.stringify(json);

          res.setHeader('Content-Type', 'application/json');
          res.setHeader('Cache-Control', 'no-store');
          res.setHeader('Pragma', 'no-cache');
          res.end(json);
        };

        issue(client, profile, socialAuthData, scope, issued);
      });
    };
  };
};
