const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const methodOverride = require('method-override');
const flash = require('connect-flash');
const randToken = require('rand-token');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv').config();
//const bcrypt = require('bcrypt');

// PASSPORT AUTHENTIFICATION
const session = require('express-session');
const passport = require('passport');
const passportLocalStrategy = require('passport-local-mongoose');

const app = express();

// MODELS
const User = require('./models/user');
const Reset = require('./models/reset');
const Receipe = require('./models/receipe');
const Ingredient = require('./models/ingredient');
const Favourite = require('./models/favourite');
const Schedule = require('./models/schedule');

// INITIALISER SESSION
app.use(session({
    secret: 'mySecret',
    resave: false, 
    saveUninitialized: false // si session non enregistrée on l'enregistre pas
}));

// INITIALISER PASSPORT
app.use(passport.initialize());
// INITIALISER LE LIEN ENTRE PASSPORT ET MA SESSION
app.use(passport.session());


// MONGOOSE
// MongoDB Atlas : compte google sandrine GMAIL
// utilisateur db : adminElvire - admin4315
mongoose.connect(process.env.DB_URI, 
    { useNewUrlParser: true,
      useUnifiedTopology: true
    })
    .then(() => console.log('Connexion à MongoDBAtlas réussie !'))
    .catch(() => console.log('Connexion à MongoDBAtlas échouée !'));

// INITIALISER PASSPORT EN LIEN AVEC NOTRE BDD 
// PASSPORT-LOCAL-MONGOOSE
// permet d'authentifier nos requêtes
passport.use(User.createStrategy());
// permet de gérer les cookies et rediriger les utilisateurs selon leurs goûts par exemple
// on a accès à toutes les infos de l'utilisateur
passport.serializeUser(User.serializeUser());
// on detruit toutes les infos de l'utilisateur, son cookie ... quand il se logout
passport.deserializeUser(User.deserializeUser());

// EJS
app.set('view engine', 'ejs');

// PUBLIC FOLDER
app.use(express.static('public'));

// BODY-PARSER
app.use(bodyParser.urlencoded({extended : false}));

// INITIALISER FLASH
app.use(flash());
// MESSAGES FLASH
app.use((req, res, next) => {
    res.locals.currentUser = req.user;
    // on pourra avoir accès dans nos pages (avec template EJS) à la variable d'environnement error
    res.locals.error = req.flash('error');
    res.locals.success = req.flash('success');
    next();
});

// INITIALISER METHOD OVERRIDE : permet de réecrire sur method=POST en spécifiant un DELETE par ex dans URL du formulaire POST
app.use(methodOverride('_method'));



// ROUTES
// HOME
app.get('/', (req, res) => {
    res.render('index');
});

// SIGNUP
app.get('/signup', (req, res) => {
    res.render('signup');
});

app.post('/signup', (req, res) => {
    const newUser = new User({
        username : req.body.username
    });
    // enregistrer ce nouvel user dans la bdd et crypter le pwd directement
    User.register(newUser, req.body.password, (err, user) => {
        if(err){
            console.error(err);
            res.render('signup');
        } else {
            // authentifier le user pour lui créer une session
            User.authenticate('local')(req, res, function(){
                res.redirect('signup');
            });
        }
    });
});

// LOGIN
app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', (req, res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, (err) => {
        if(err){
            console.error(err);
        } else {
            passport.authenticate('local')(req, res, () => {
                res.redirect('/dashboard');
            });
        }
    });
});

// DASHBOARD
app.get('/dashboard', isLoggedIn, (req, res) => {
    //console.log(req.user);
    res.render('dashboard');
});


// LOGOUT
app.get('/logout', (req, res) => {
    req.logout();
    req.flash('success', 'Thank you, you are now logged out')
    res.redirect('/login');
});


// FORGOT
app.get('/forgot', (req, res) => {
    res.render('forgot');
});

app.post('/forgot', (req, res) => {
    // check si user existe bien dans la bdd
    User.findOne({ username : req.body.username }, (err, userFound) => {
        if(err){
            console.error(err);
            res.redirect('/login');
        } else {
            // le user existe et veut réinitialiser son mdp : on lui créé un token
            // générer token aléatoire avec rand-token
            const token = randToken.generate(16);
            //console.log(token);
            // on veut mettre ce token dans une collection (table) "reset" dans la bdd
            Reset.create({
                username: userFound.username,
                resetPasswordToken: token,
                resetPasswordExpires : Date.now() + 3600000 //1h
            });
            // evite erreur sur certificat
            process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
            // envoyer un mail à user avec nodemailer
            const transporter = nodemailer.createTransport({
                service: 'gmail',
                // compte à partir duquel on envoie le mail
                auth: {
                    user: 'cooking4393@gmail.com',
                    pass: process.env.PWD
                }
            });
            const mailOptions = {
                from: 'cooking4393@gmail.com',
                to: req.body.username,
                subject: 'link to reset your password',
                text: 'click on this link to reset your password : http://localhost:3000/reset/'+token
            }
            console.log('le mail est prêt à être envoyé');

            transporter.sendMail(mailOptions, (err, response) => {
                if(err){
                    console.error(err);
                } else {
                    req.flash('success', 'Successfully sent you an email!');
                    res.redirect('/login');
                }
            });
        }
    });
});

// RESET TOKEN : lien reçu par utilisateur qui a demandé un nvo mdp
// Renvoyer l'utilisateur qui a son token valide vers une page reset
app.get('/reset/:token', (req, res) => {
    // check si token existe et non expiré
    Reset.findOne({
        resetPasswordToken: req.params.token,
        resetPasswordExpires: {
            $gt: Date.now() // date d'expiration > à date actuelle
        } 
    }, (err, obj) => {
        if(err){
            console.error('token expired');
            req.flash('error', 'Token expired!');
            res.redirect('/login');
        } else {
            // s'il a trouvé un objet (token) valide
            // on redirige vers page reste et on veut récupérer le token dans le form avec EJS
            res.render('reset', {
                token: req.params.token
            });
        }
    })
});
// MODIFIER LE MDP DU CLIENT
// 1-check que token tjs valide 2-check que l'utilisateur existe bien 3-ckeck que les pwd1 et 2 sont égaux. Si oui, on peut modifier son mdp et update la table reset qui contient le token et le mettre à null
app.post('/reset/:token', (req, res) => {
    Reset.findOne({
        resetPasswordToken: req.params.token,
        resetPasswordExpires: {
            $gt: Date.now() // date d'expiration > à date actuelle
        }
    }, (err, obj) => {
        if(err){
            console.error('token expired');
            req.flash('error', 'Token expired!');
            res.redirect('/login');
        } else { // token valide
            // si les 2 mdp sont égaux
            if(req.body.password == req.body.password2){
                // check si user existe dans la bdd
                User.findOne({ username: obj.username }, (err, user) => {
                    if(err){
                        console.error(err);
                        req.flash('error', 'User not found with this email!');
                    } else { // user existe
                        // modifier et actualiser le mdp grâce à passportJS
                        user.setPassword(req.body.password, (err) => {
                            if(err){
                                console.error(err);
                            } else {
                                // sauvegarde le user avec le nvo mdp dans la collection user
                                user.save();
                                // actualiser le token à null
                                const updatedReset = {
                                    resetPasswordToken: null,
                                    resetPasswordExpires: null
                                }
                                // actualiser la collection reset
                                // recherche le token (celui passé en paramètre) dans collection reset et on le modifie par le nouvel objet passé à null
                                Reset.findOneAndUpdate({resetPasswordToken: req.params.token}, updatedReset, (err, obj1) => {
                                    if(err) {
                                        console.error(err);
                                    } else {
                                        res.redirect('/login');
                                    }
                                });
                            }
                        });
                    }
                });
            }
        }
    });
});

// MY RECEIPES ROUTE
app.get('/dashboard/myreceipes', isLoggedIn, (req, res) => {
    // récupérer toutes les recettes de l'utilisateur connecté
    Receipe.find({
        user: req.user.id
    }, (err, receipeFound) => {
        if(err) {
            console.error(err);
        } else {
            res.render('receipe', { receipe: receipeFound });
        }
    });
});

// NEW RECEIPE ROUTE
app.get('/dashboard/newreceipe',isLoggedIn, (req, res) => {
    res.render('newreceipe');
});

// créer nouvelle recette dans bdd
app.post('/dashboard/newreceipe', (req, res) => {
    // récupérer les infos rentrés dans le form par le user dans une nouvelle recette
    const newReceipe = {
        name: req.body.receipe,
        image: req.body.logo,
        user: req.user.id
    }

    // sauvegarder la recette en bdd
    Receipe.create(newReceipe, (err, newReceipe) => {
        if(err) {
            console.error(err);
        } else {
            req.flash('success', 'new receipe added!');
            res.redirect('/dashboard/myreceipes');
        }
    });
});

// ROUTE RECETTE SPECIFIQUE AVEC SES INGREDIENTS
app.get('/dashboard/myreceipes/:id', (req, res) => {
    // check que la recette existe : que la receipe en base (_id) corresponde bien à l'id passé dans l'url
    // check aussi que le user qui essaye de regarder la recette est bien celui qui a créer cette recette
    Receipe.findOne({user: req.user.id, _id: req.params.id}, (err, receipeFound) => {
        if(err) {
            console.error(err);
        } else {
            // on va chercher les ingredients de la recette
            Ingredient.find({
                user: req.user.id,
                receipe: req.params.id
            }, (err, ingredientFound) => {
                if(err) {
                    console.error(err);
                } else {
                    // afficher la page ingredients
                    res.render('ingredients', {
                        ingredient: ingredientFound,
                        receipe: receipeFound
                    });
                }
            });
        }
    });
});

// SUPPRIMER RECETTE
app.delete('/dashboard/myreceipes/:id',isLoggedIn, (req, res) => {
    Receipe.deleteOne({_id: req.params.id}, (err) => {
        if(err){
            console.error(err);
        } else {
            req.flash('success', 'the receipe has been deleted');
            res.redirect('/dashboard/myreceipes');
        }
    });
});

// CREER INGREDIENT
app.get('/dashboard/myreceipes/:id/newingredient', (req, res) => {
    // check que la recette existe encore
    Receipe.findById({_id: req.params.id}, (err, receipeFound) => {
        if(err){
            console.error(err);
        } else {
            // afficher page newingredient et l'objet recette trouvée qui permettra d'afficher l'image de la recette dans template EJS
            res.render('newingredient', {receipe: receipeFound})
        }
    });
});

// AJOUTER LES INGREDIENTS
app.post('/dashboard/myreceipes/:id', (req, res) => {
    // récupérer les infos du formulaire
    const newIngredient = {
        name: req.body.name,
        bestDish: req.body.dish,
        user: req.user.id,
        quantity: req.body.quantity,
        receipe: req.params.id
    }
    // enregistrer ingredient dans la bdd
    Ingredient.create(newIngredient, (err, newIngredient) => {
        if(err){
            console.error(err);
        } else {
            req.flash('success', 'your ingredient has been added!');
            res.redirect('/dashboard/myreceipes/'+req.params.id);
        }
    });
});

// SUPPRIMER INGREDIENT
app.delete('/dashboard/myreceipes/:id/:ingredientid', isLoggedIn, (req, res) => {
    Ingredient.deleteOne({_id: req.params.ingredientid}, (err) => {
        if(err) {
            console.error(err);
        } else {
            req.flash('success', 'your ingredient has been deleted!');
            res.redirect('/dashboard/myreceipes/'+ req.params.id);
        } 
    });
});

// MODIFIER UN INGREDIENT: recupérer recette et ingrédient à modifier et afficher page edit.ejs
app.post('/dashboard/myreceipes/:id/:ingredientid/edit', isLoggedIn, (req, res) => {
    // check si recette existe toujours
    Receipe.findOne({user: req.user.id, _id: req.params.id}, (err, receipeFound) => {
        if(err){
            console.error(err);
        } else {
            // on cherche notre ingrédient
            Ingredient.findOne({
                _id: req.params.ingredientid,
                receipe: req.params.id
            }, (err, ingredientFound) => {
                if(err){
                    console.error(err);
                } else {
                    // on renvoie dans notre page edit l'ingredient et la recette trouvés pour être utilisés avec EJS en output
                    res.render('edit', {
                        ingredient: ingredientFound,
                        receipe: receipeFound
                    });
                }
            });
        }
    });
});

// MODIFIER INGREDIENT : METHOD PUT
app.put('/dashboard/myreceipes/:id/:ingredientid',isLoggedIn, (req, res) => {
    // créer un nouvel objet qui remplacera l'objet dans la table
    const ingredientUpdated = {
        name: req.body.name,
        bestDish: req.body.dish,
        user: req.user.id,
        quantity: req.body.quantity,
        receipe: req.params.id
    }
    // actualiser la collection ingrédient
    // vérifier aussi s'il existe bien et si oui on l'update
    Ingredient.findByIdAndUpdate({_id: req.params.ingredientid}, ingredientUpdated, (err, updatedIngredient) => {
        if(err){
            console.error(err);
        } else {
            req.flash('success', 'Successfully updated ingredient!');
            res.redirect('/dashboard/myreceipes/'+req.params.id);
        }
    });
});

// FAVOURITES ROUTES
app.get('/dashboard/favourites', isLoggedIn, (req, res) => {
    // récupérer toutes les recettes favorites 
    Favourite.find({user: req.user.id}, (err, favourite) => {
        if(err){
            console.error(err);
        } else {
            res.render('favourites', {favourite : favourite});
        }
    });

});

// AJOUTER RECETTE FAVORITE
// ACCEDER A LA PAGE NEW FAVOURITE
app.get('/dashboard/favourites/newfavourite', isLoggedIn, (req, res) => {
    res.render('newfavourite');
});

app.post('/dashboard/favourites', isLoggedIn, (req, res) => {
    // récupérer les infos du formulaire
    const newFavourite = {
        image: req.body.image,
        title: req.body.title,
        description: req.body.description,
        user : req.user.id
    }
    // ajouter ce nouvel objet dans collection favourite
    Favourite.create(newFavourite, (err, newFavourite) => {
        if(err){
            console.error(err);
        } else {
            req.flash('success', 'you just added a new fav!');
            res.redirect('/dashboard/favourites');
        }
    });
});

app.delete('/dashboard/favourites/:id', isLoggedIn, (req, res) => {
    Favourite.deleteOne({_id: req.params.id}, (err) => {
        if(err){
            console.error(err);
        } else {
            req.flash('success', 'your fav has been deleted!');
            res.redirect('/dashboard/favourites');
        }
    });
});

// SCHEDULE ROUTES
app.get('/dashboard/schedule', isLoggedIn, (req, res) => {
    // recherche tous les schedules dans la collection Schedule
    Schedule.find({user: req.user.id}, (err, schedule) => {
        if(err){
            console.error(err);
        } else {
            // puis rediriger dans la page shedule.ejs
           res.render('schedule', {schedule: schedule});
        }
    })
});

// AJOUTER UNE NOUVELLE PROGRAMMATION DE RECETTE
app.get('/dashboard/schedule/newschedule', isLoggedIn, (req, res) => {
    res.render('newschedule');
});

app.post('/dashboard/schedule', isLoggedIn, (req, res) => {
    // récupérer les infos du client
    const newSchedule = {
        receipeName: req.body.receipename,
        scheduleDate: req.body.scheduleDate,
        user : req.user.id,
        time: req.body.time
    }
    // on ajoute le schedule dans la bdd
    Schedule.create(newSchedule, (err, newSchedule) => {
        if(err){
            console.error(err);
        } else {
            req.flash('success', 'you just added a new schedule!');
            res.redirect('/dashboard/schedule');
        }
    });
});

// SUPPRIMER UNE PROGRAMMATION
app.delete('/dashboard/schedule/:id', isLoggedIn, (req, res) => {
    Schedule.deleteOne({_id: req.params.id}, (err) => {
        if(err){
            console.error(err);
        } else {
            req.flash('success', 'your schedule has been deleted!');
            res.redirect('/dashboard/schedule');
        }
    });
});

// FONCTION DE USER CONNECTE OU PAS
// savoir si notre utilisateur est connecté
function isLoggedIn(req, res, next){
    // propriété de passportJS
    if(req.isAuthenticated()) {
        // si connecté, on peut exécuter le reste du code (placé derrière isLoggedIn dans notre code)
        return next();
    } else {
        req.flash('error', 'Please login first!');
        res.redirect('/login');
    }
}




app.listen(3000, () => {
    console.log('server is running on port 3000.');
});