module.exports = function (name, message, data) {
	data = data || {};
	if (!name) {
		console.warn(_name + ' input argument *name* is missing');
		return;
	}
	if (data.name) console.warn(_name + ' input agrument *data.name* was overwritten');
	if (data.message) console.warn(_name + ' input agrument *data.messaage* was overwritten');
	data.name = name;
	data.message = message || {};
	return data;
};