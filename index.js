require('dotenv').config();
const express = require('express');
const path = require('path');
const morgan = require('morgan');
const app = express();
const cors = require('cors');
const jwksRsa = require('jwks-rsa');
const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;


const { User, Pet } = require('./db');


// Application Level Middleware
const corsOptions = {
  //TODO - UPDATE TO PRODUCTION PATH
  origin: ['http://localhost:3000', 'http://localhost:4000'],
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization']
};

const {
  AUTH0_AUDIENCE,
  AUTH0_BASE_URL,
} = process.env;

app.use(cors(corsOptions));
app.use(morgan('dev'));
app.use((req, res, next) => {
  console.log('Request Headers:', req.headers);
  next();
});
app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(express.static(path.join(__dirname, 'build')));

// Authentication Initialization
const opts = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `${AUTH0_BASE_URL}/.well-known/jwks.json`
  }),
  audience: AUTH0_AUDIENCE,
  issuer: `${AUTH0_BASE_URL}/`,
  algorithms: ['RS256']
};

passport.use(new JwtStrategy(opts, (jwt_payload, done) => {
  return done(null, jwt_payload);
}));

app.use(passport.initialize());

const isAdmin = (user) => {
  if(user.admin == true) return user;
}

async function findOrCreateUser(jwtPayload) {
  try {
    let user = await User.findOne({ auth0Id: jwtPayload.sub });

    if (!user) {
        user = new User({
            auth0Id: jwtPayload.sub,
            name: jwtPayload.name || "", 
            email: jwtPayload.email || "", 
        });
        await user.save();
    }
    return user;
  } catch (err) {
    throw err;
  }
}

app.get('/', (req, res) => {
  res.json({
    message: "Pet Adoption Center API",
    version: "1.0.0"
  });
});


// GET all pets route
app.get('/pets', passport.authenticate('jwt', { session: false }), async (req, res, next) => {
  try {
    const user = await findOrCreateUser(req.user);
    let pets;

    pets = await Pet.findAll({ where: { userId: user.id } });
    
    return res.send(pets);
  } catch (error) {
    console.error('get /pets error:', error);
    next(error);
  }
});

// Protected route to create a new pet
app.post('/pets', passport.authenticate('jwt', { session: false }), async (req, res, next) => {
  const user = await findOrCreateUser(req.user);
  if (!user) {
    return res.status(401).send({ error: 'You must be logged in to create a pet!' });
  } else {
    try {
      const { name, breed, age, weight } = req.body;
      const newPet = await Pet.create({ name, breed, age, weight, userId: user.id });
      user.addPet(newPet);
      res.send(newPet);
    } catch (error) {
      console.error('post /pets error:', error);
      next(error);
    }
  }
});

//Protected route to get a pet and it's associated user
app.get('/pets/:id' , passport.authenticate('jwt', { session: false }), async (req, res, next) => {
  const pet = await Pet.findOne({where: {id: req.params.id}, include: User}) 
  if (pet === null) {
    res.status(404).json({error: "Pet not found."})
  } else {
    res.json(pet)
  }
})

// Protected route to delete a pet
app.delete('/pets/:id', passport.authenticate('jwt', { session: false }), async (req, res, next) => {
  try {
    const { id } = req.params;
    const user = await findOrCreateUser(req.user);
    const petExistCheck = await Pet.findOne({where: {id}})
    const petWithAuth = await Pet.findOne({ where: { id, userId: user.id } });
    if (!petExistCheck) {
      return res.status(404).send({ error: 'Pet not found.' });
    } else if (!petWithAuth && !isAdmin(user)) {
      return res.status(401).send({error: 'User not authorized to modify this pet.'})
    } else {
      await petWithAuth.destroy();
      res.send({ message: 'Pet deleted successfully.' });
    }
  } catch (error) {
    console.error('delete /pets/:id error:', error);
    next(error);
  }
});

// As a User, I want to edit entries in the database
app.put('/pets/:id', passport.authenticate('jwt', { session: false }), async (req, res, next) => {
  try {
    const { id } = req.params;
    const { name, age, breed, weight } = req.body;
    const user = await findOrCreateUser(req.user);
    let pet;

    //If the user is an admin, they may edit any pet in the db.
    if (isAdmin(user)) {
      pet = await Pet.findOne({ where: { id } });
    } else {
      pet = await Pet.findOne({ where: { id, userId: req.user.username } });
    }
    
    //If the pet is found based on the above criteria, the edits will apply.
    if (!pet) {
      return res.status(404).send({ error: 'Pet not found.' });
    } else {
      //Only update the parameters if they are provided
      if (name !== undefined) pet.name = name;
      if (age !== undefined) pet.age = age;
      if (breed !== undefined) pet.breed = breed;
      if (weight !== undefined) pet.weight = weight;
      await pet.save();
      return res.send({ message: 'Pet updated successfully!', pet: pet });
    }
  } catch (error) {
    console.error('put /pets/:id error:', error);
    return next(error);
  }
});

app.use((err, req, res, next) => {
  if (err.name === 'UnauthorizedError') {
    return res.status(401).send({ error: 'Invalid or missing token.' });
  }
  next(err);
});

app.use((error, req, res, next) => {
  console.error('SERVER ERROR: ', error);
  if(res.statusCode < 400) res.status(500);
  res.send({error: error.message, name: error.name, message: error.message});
});

module.exports = { app };