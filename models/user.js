const mongoose = require('mongoose');
// permet de salt et hasher le mdp dans la bdd
const passportLocalMongoose = require('passport-local-mongoose');

const UserSchema = new mongoose.Schema({
    username: String,
    password: String
});

// ce plugin va enregistrer automatiquement un password hashé et un salt-round dans la DB
UserSchema.plugin(passportLocalMongoose);

module.exports = mongoose.model('User', UserSchema);