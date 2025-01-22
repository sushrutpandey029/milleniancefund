import multer from 'multer';
import path from 'path';

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'Views/src/ProfileImage/'); // Directory where the files will be saved
    },
    filename: (req, file, cb) => {
        const filename = `${Date.now()}-${Math.round(Math.random() * 1E9)}${path.extname(file.originalname)}`;
        cb(null, filename); // Save only the filename
    }
});

const ProfileUpload = multer({ storage: storage });

export default ProfileUpload;
