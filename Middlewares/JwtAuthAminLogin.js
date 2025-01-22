import jwt from 'jsonwebtoken';

export const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (authHeader) {
        const token = authHeader.split(' ')[1]; // Extract token from Bearer scheme

        jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
            if (err) {
                return res.status(403).send({ message: "Invalid or expired token." });
            }
            req.user = user;
            next();
        });
    } else {
        return res.status(401).send({ message: "Unauthorized. Token is missing." });
    }
};
