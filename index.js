require('dotenv').config();
const express = require('express');
const path = require('path');
const morgan = require('morgan');
const { auth, requiresAuth } = require('express-openid-connect');
const app = express();
const cors = require('cors');

const { User, Pet } = require('./db');

// middleware
const corsOptions = {
  //TODO - UPDATE TO PRODUCTION PATH
  origin: ['http://localhost:3000', 'http://localhost:4000'],
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization']
};

//AUTHENTICATION middleware
const {
  AUTH0_SECRET,
  AUTH0_CLIENT_SECRET,
  AUTH0_AUDIENCE,
  AUTH0_CLIENT_ID,
  AUTH0_BASE_URL,
} = process.env;

const config = {
  authRequired: false,
  auth0Logout: true,
  secret: AUTH0_SECRET,
  baseURL: AUTH0_AUDIENCE,
  clientID: AUTH0_CLIENT_ID,
  clientSecret: AUTH0_CLIENT_SECRET,
  issuerBaseURL: AUTH0_BASE_URL,
  authorizationParams: {
    response_type: 'code',
    response_mode: 'query'
  }
};

app.use(cors(corsOptions));
app.use(auth(config));
app.use((req, res, next) => {
  console.log('OIDC data:', req.oidc);
  next();
});
app.use(morgan('dev'));
app.use(express.json());
app.use(express.urlencoded({extended:true}));

app.use(express.static(path.join(__dirname, 'build')));

const isAdmin = (user) => {
  if(user.admin == true) return user;
}

const findOrCreateUser = async (user) => {
  if (!user || !user.sub) {
    throw new Error('User data is missing.');
  }
  console.log('user:', user);

  try {
    let userRecord = await User.findOne({ where: { auth0Id: user.sub } });
    console.log('userRecord:', userRecord);
    if (!userRecord) {
      console.log(user);
      userRecord = await User.create({
        auth0Id: user.sub,
        name: user.name,
        email: user.email,
        admin: false
      });
    }
    return userRecord;
  } catch (error) {
    console.error(error);
  }
}

app.get('/', async (req, res) => {
  if (req.oidc.isAuthenticated()) {
    res.redirect('/dashboard');
  } else {
    res.redirect('/login');
  }
});

// GET all pets route
app.get('/pets', async (req, res, next) => {
  if (!req.oidc.isAuthenticated()) {
    return res.status(401).send({ error: 'You must be logged in to see your pets!' });
  }
  
  console.log(req.oidc.user);

  try {
    const user = await findOrCreateUser(req.oidc.user);
    let pets;

    if (isAdmin(user)) {
      pets = await Pet.findAll(); // Admin should be able to view all pets
    } else {
      pets = await Pet.findAll({ where: { userId: user.id } });
    }
    
    return res.send(pets);
  } catch (error) {
    console.error(error);
    next(error);
  }
});


// Protected route to create a new pet
app.post('/pets', requiresAuth(), async (req, res, next) => {
  const user = await findOrCreateUser(req.oidc.user);
  if (!req.oidc.user) {
    res.sendStatus(401).send({ error: 'You must be logged in to create a pet!' });
  } else {
    try {
      const { name, breed, age, weight } = req.body;
      const newPet = await Pet.create({ name, breed, age, weight, userId: user.id });
      user.addPet(newPet);
      res.send(newPet);
    } catch (error) {
      console.error(error);
      next(error);
    }
  }
});

//Protected route to get a pet and it's associated user
app.get('/pets/:id' , requiresAuth(), async (req, res, next) => {
  const pet = await Pet.findOne({where: {id: req.params.id}, include: User}) 
  if (pet === null) {
    res.status(404).json({error: "Pet not found."})
  } else {
    res.json(pet)
  }
})

// Protected route to delete a pet
app.delete('/pets/:id', requiresAuth(), async (req, res, next) => {
  try {
    const { id } = req.params;
    const user = await findOrCreateUser(req.oidc.user);
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
    console.error(error);
    next(error);
  }
});

// As a User, I want to edit entries in the database
app.put('/pets/:id', requiresAuth(), async (req, res, next) => {
  try {
    const { id } = req.params;
    const { name, age, breed, weight } = req.body;
    const user = await findOrCreateUser(req.oidc.user);
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
    console.error(error);
    return next(error);
  }
});

app.get('/token', (req, res) => {
  if (!req.oidc) {
    res.send({ error: "OIDC data missing" });
    return;
  }
  if (!req.oidc.accessToken) {
    res.send({ error: "Access token missing" });
    return;
  }
  try {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.send({ accessToken: req.oidc.accessToken });
    console.log('this is the access token:', req.oidc.accessToken);
  } catch {
    res.send({ status: 401, message: "Not authenticated" });
  }
});

app.use((error, req, res, next) => {
  console.error('SERVER ERROR: ', error);
  if(res.statusCode < 400) res.status(500);
  res.send({error: error.message, name: error.name, message: error.message});
});

module.exports = { app };