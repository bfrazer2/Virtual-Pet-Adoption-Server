const {sequelize} = require('.');
const seed = require('./seedFn');

seed()
  .then(() => {
    console.log('Seeding success. Pet Adoption Center to the Rescue!');
  })
  .catch(err => {
    console.error(err);
  })
  .finally(() => {
    sequelize.close();
  });
  