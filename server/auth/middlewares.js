const isAuth = (req, res, next) => {
    if(req.user){
        next()
    }else if(req.user){
        next()
    }else{
        res.status(401).send('Unauthorized')
    }
}

const isAdmin = (req, res, next) => {
    if(req.user && req.user.isAdmin){
        next()
    }else{
        res.status(400).send('Acces forbiden')
    }
}

module.exports = {
    isAuth,
    isAdmin
}