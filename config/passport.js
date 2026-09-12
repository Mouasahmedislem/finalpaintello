var passport = require('passport');
var User = require('../models/user');
var LocalStrategy = require('passport-local').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;

const fbAppId = process.env.FACEBOOK_APP_ID;
const fbAppSecret = process.env.FACEBOOK_APP_SECRET;

if (fbAppId && fbAppSecret) {
  passport.use(new FacebookStrategy({
    clientID: fbAppId,
    clientSecret: fbAppSecret,
    callbackURL: "https://www.paintello.uk/auth/facebook/callback",
    profileFields: ['id', 'emails', 'name'] // Request email, first and last name
  }, async function(accessToken, refreshToken, profile, done) {
    try {
      const existingUser = await User.findOne({ 'facebookId': profile.id });

      if (existingUser) return done(null, existingUser);

      // If not found, create new user
      const newUser = new User({
        facebookId: profile.id,
        email: profile.emails?.[0].value || `user_${profile.id}@facebook.com`,
        firstName: profile.name.givenName || '',
        lastName: profile.name.familyName || '',
        numero: '', // Facebook doesn't provide phone number
        isAdmin: false
      });

      await newUser.save();
      return done(null, newUser);
    } catch (err) {
      return done(err, null);
    }
  }));
} else {
  console.log('⚠️ FACEBOOK_APP_ID / FACEBOOK_APP_SECRET not provided - Facebook Auth disabled.');
}

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(async function(id, done) {
  try {
    const user = await User.findById(id).exec();
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// Local Signup Strategy
passport.use(
  "local-signup",
  new LocalStrategy(
    {
      usernameField: "email",
      passwordField: "password",
      passReqToCallback: true,
    },
    async function (req, email, password, done) {
      try {
        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) {
          return done(null, false, req.flash("signupMessage", "L'email existe déjà."));
        } else {
          const newUser = new User();
          newUser.email = email.toLowerCase();
          newUser.password = newUser.encryptPassword(password);
          newUser.firstName = req.body.firstName.toLowerCase();
          newUser.lastName = req.body.lastName.toLowerCase();
          newUser.numero = req.body.numero;
          await newUser.save();
          return done(null, newUser);
        }
      } catch (err) {
        return done(err);
      }
    }
  )
);


// SIGNIN
passport.use('local-signin', new LocalStrategy({
  usernameField: 'email',
  passwordField: 'password',
  passReqToCallback: true
}, async function(req, email, password, done) {
  req.assert('email', 'invalid email').notEmpty().isEmail();
  req.assert('password', 'invalid password (must be more than 4 characters)').notEmpty();
  var errors = req.validationErrors();
  if (errors) {
    var messages = errors.map(error => error.msg);
    return done(null, false, req.flash('error', messages));
  }

  try {
    const user = await User.findOne({ email }).exec();
    if (!user) {
      return done(null, false, { message: 'No user found.' });
    }

    if (!user.validPassword(password)) {
      return done(null, false, { message: 'Wrong password.' });
    }

    req.session.user = {
      email: user.email,
      numero: user.numero,
      firstName: user.firstName,
      lastName: user.lastName
    };

    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));
