const validateBody = (body , extendedSchema) => {
    const { error, value } = extendedSchema.validate(body);

    if (error) {
    
            return null;
    }

    return value; 
}

const checkFormat = (body , joiSchema) => {
   
    const extendedSchema = joiSchema;
   
    const validated = validateBody(body , extendedSchema);
    if(validated == null){
        return false;
    }
    else{
        return true;
    }


}

module.exports = checkFormat;