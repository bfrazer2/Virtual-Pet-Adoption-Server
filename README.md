# Welcome to your Virtual Pet Adoption Center!

Currently this project is a deployed API which displays JSON on the front end as a representation of database elements. Below are instructions for getting it up and running.

## Setup

### Login
 1. Navigate to the deployed site using this link: https://virtual-pet-adoption.onrender.com/
 2. Login using the Auth0 interface

### Setting up Postman
 1. Use the contents of the collection.json file in this repo to import the Postman collection which can be used to test the application.
 2. Within the collection, navigate to and click the "Cookies" button below the "Send" button on the request interface.
 3. Navigate to the "Sync Cookies" tab, and add `dev-24y7l027nszyyovt.us.auth0.com` to the domains being intercepted. 
4. Click "Start Syncing"

### Running the Tests
1. You may now run any of the routes in the postman collection.
2. Please note that routes which use a pet-id in the URL will need to be edited to match the pet-id you are trying to interact with.
3. The routes are set in an order which should make this simpler; the first route will create your very first virtual pet, and the second will retrieve information about all pets associated with your account! The response from that get route will include the ID of any pets that you have ownership of!

### Docker Container

1. Install Docker
2. Navigate to the root of this directory in your terminal
3. Run docker build . -t virtual-pet-adoption
4. Run docker run --rm -p 4000:4000 virtual-pet-adoption
5. Browse to http://localhost:4000 (on macOS and Windows browse to http://192.168.99.100:4000 if you are using docker-machine instead of the native docker installation)

And that's all there is to it! Happy pet creation :)


# Multiverse back-end module project
***
Divya Ranat, Mia Huggins,  Ben, Frazer, Pierre Nguyen
