function vulnerableQuery(userId) {
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    console.log(`Executing query: ${query}`);
    db.all(query, [], (err, rows) => {
        if (err) {
            throw err;
        }
        console.log('Query results:', rows);
    });
}

module.exports = {
    vulnerableQuery
};