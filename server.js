/***************************************************
 * ScalaMed Auth Service
 * --------------------
 *
 * This service acts as the authentication point of
 * contact for the ScalaMed web app and verifies if
 * users have permission to perform actions based 
 * on their provided token.
 *
 ***************************************************/


///////////////
// Packages
///////////////

const express = require('express')
const https = require('https')
const bodyparser = require('body-parser')
const jwt = require('express-jwt')


///////////////
// Server Setup
///////////////



const port = process.env.SERVERPORT || 8443
const host = process.env.HOST || 'localhost'

//TODO set up HTTPS

///////////////
// API Endpoints
///////////////

/**
 * Login
 *
 */

/**
 * Register
 *
 */


/**
 * Check
 *
 */

/**
 * Forgot pw
 *
 */

///////////////
// Server Start
///////////////


