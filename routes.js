const passport = require('passport');
const LocalStrategy = require('passport-local');
const bcrypt = require('bcrypt');
const ObjectID = require('mongodb').ObjectID;

module.exports = function(app, myDataBase) {

 var showLogin = false
  app.route('/').get((req, res) => {
      showLogin =!showLogin
    // Change the response to render the Pug template
    res.render('pug', { title: 'Connected to Database', message: 'Please login', showLogin: showLogin, showRegistration: !showLogin,showSocialAuth: true });
  });


  app.route('/login').post(passport.authenticate('local', { failureRedirect: '/' }), (req, res) => {
    res.redirect('/profile');
  });





  app.route('/profile').get(ensureAuthenticated, (req, res) => {
    res.render(process.cwd() + '/views/pug/profile', { username: req.user.username });
  });



  app.route('/logout').get((req, res) => {
    req.logout();
    res.redirect('/');
  });

  // The logic of step 1, registering the new user, should be as follows: Query database with a findOne command > if user is returned then it exists and redirect back to home OR if user is undefined and no error occurs then 'insertOne' into the database with the username and password, and, as long as no errors occur, call next to go to step 2, authenticating the new user, which we've already written the logic for in our POST /login route.

  app.route('/register').post(
    (req, res, next) => {
      const hash = bcrypt.hashSync(req.body.password, 12);

      myDataBase.findOne({ username: req.body.username }, function(err, user) {
        if (err) {
          next(err);
        } else if (user) {
          res.redirect('/');
        } else {
          myDataBase.insertOne({ username: req.body.username, password: hash }, (err, doc) => {
            if (err) {
              res.redirect('/');
            } else {
              next(null, doc.ops[0]);
            }
          });
        }
      });
    },
    passport.authenticate('local', { failureRedirect: '/' }),
    (req, res, next) => {
      res.redirect('/profile');
    }
  );

 app.route('/auth/github').get(passport.authenticate('github'));
  app.route('/auth/github/callback').get(passport.authenticate('github', { failureRedirect: '/' }), (req, res) => {
   req.session.user_id = req.user.id;
    res.redirect('/profile');
  });


//new
 app.get('/auth/google',
  passport.authenticate('google', { scope:
      [ 'email', 'profile' ] }
));
  app.route('/auth/google/callback').get(passport.authenticate('google', { failureRedirect: '/' }), (req, res) => {
   req.session.user_id = req.user.id;
    res.redirect('/profile');
  });
//
 app.get('/auth/facebook',
  passport.authenticate('facebook', { scope: ['user_friends', 'manage_pages'] }));
  app.route('/auth/facebook/callback').get(passport.authenticate('facebook', { failureRedirect: '/' }), (req, res) => {
   req.session.user_id = req.user.id;
    res.redirect('/profile');
  });


  app.use((req, res, next) => {
    res.status(404).type('text').send('Not Found');
  });
  function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
      return next();
    }
    res.redirect('/');
  }
}
