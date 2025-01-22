import { Sequelize } from "sequelize";

const sequelize  = new Sequelize('Milleniance_Account','root','root@123',{
    host: '127.0.0.1',  // Replace with the actual hostname
  dialect: 'mysql',
  port: 3306  // Default MySQL port
});

const Db_connetion= async()=>{
    try{
        await sequelize.authenticate();
        console.log("db connect successfuly")

    }catch(err){
        console.error("Error while connecting to the database", err);
    }
};

Db_connetion();

export default sequelize;

// const sequelize  = new Sequelize('milleniancecom_ddsp_app','milleniancecom_ddspapp','@$e$4~bzK5SS',{
//     host: '68.178.173.163',  // Replace with the actual hostname
//   dialect: 'mysql',
//   port: 3306  // Default MySQL port
// });