const util = require("util");
const exec = util.promisify(require('child_process').exec);


async function invokeCPP (fields , path){
    // fields is an array of strings that is to be invoked with a particular algorithim
    // algorithim is the name of the algortihim that we are going to use

    var result;
    // separate each of the strings by whitespace as a delimiter
    // inside the CPP code argv[0] is file path rest are strings
    try {
        const { stdout } = await exec(`${path} ${fields.join(' ')}`);
        const result = stdout.trim().split(' ');
        return result;
    } catch (err) {
        // console.error('Crashed');
        return "Crashed";
    }

}

module.exports = invokeCPP