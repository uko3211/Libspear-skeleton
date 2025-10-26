function unsafeDeserialize(jsonString) {
    console.log('Deserializing:', jsonString);
    const obj = JSON.parse(jsonString);
    console.log('Deserialized object:', obj);
    return obj;
}

module.exports = {
    unsafeDeserialize
};