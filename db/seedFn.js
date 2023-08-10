const { sequelize } = require('.');
const { User, Pet } = require('./index');
const { users, pets } = require('./seedData');

const seed = async () => {
  try {
    await sequelize.sync({ force: true }); // recreate db
    const createdUsers = await User.bulkCreate(users);
    const createdPets = await Pet.bulkCreate(pets);
    for(let i=0; i<createdPets.length; ++i){
        let pet = createdPets[i];
        let user = createdUsers[i % 2];
        await user.addPet(pet);
    }
  } catch (error) {
    console.error(error);
  }
};

module.exports = seed;
