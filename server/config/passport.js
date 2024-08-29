const passport = require('passport')
const User = require('../auth/User')
const bcrypt = require('bcrypt')
const LocalStrategy = require('passport-local')
const GoogleStrategy = require('passport-google-oauth20').Strategy
//CLIENT_ID : 720023655102-3fe2v9mk0v1rqi2up5m81h765ec53r9m.apps.googleusercontent.com
//CLIENT_SECRET : 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

passport.use(new LocalStrategy(
    {
        usernameField: 'email'
    },
    function(email, password, done){
        User.findOne({email}).then(user => {
            if(user.password){
                bcrypt.compare(password, user.password, function(err, result) {
                    if(err){
                        return done(err)
                    }
                    if(result){
                        return done(null, user)
                    }
                });
            }else{
                return done('Пользователь не найден')
            }
        }).catch(e => {
            return done(e)
        })
    }
))

passport.use(new GoogleStrategy({
    clientID: '720023655102-3fe2v9mk0v1rqi2up5m81h765ec53r9m.apps.googleusercontent.com',
    clientSecret: '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',
    callbackURL: "http://localhost:8000/api/auth/google",
    scope: ['openid', 'email', 'profile']
  },
  async function(accessToken, refreshToken, profile, cb) {
    const user = await User.find({googleId: profile.id})
    const newUser = await new User({
        googleId: profile.id,
        full_name: profile.displayName,
        email: profile.emails[0].value
    }).save()
    return cb(null, newUser)
  }
))

passport.serializeUser(function(user, done){
    done(null, user._id)
})

passport.deserializeUser(function(id, done) {
    User.findById(id).then((user, err) => {
        done(err, user)
    })
})