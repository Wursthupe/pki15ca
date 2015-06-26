# Imports
from flask import Flask, jsonify, abort, make_response, request, url_for

# Flask-App erstellen
app = Flask(__name__)

# Start-Datensatz
tasks = [
    {
        'id': 1,
        'title': u'Buy groceries',
        'description': u'Milk, Cheese, Pizza, Fruit, Tylenol', 
        'done': False
    },
    {
        'id': 2,
        'title': u'Learn Python',
        'description': u'Need to find a good Python tutorial on the web', 
        'done': False
    }
]

# Schöneres Fehlerhandling
@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)

# ID in Rückgabe durch URL ersetzen können (ID ist für Client unwichtig)
def make_public_task(task):
    new_task = {}
    for field in task:
        if field == 'id':
            new_task['uri'] = url_for('get_task', task_id=task['id'], _external=True)
        else:
            new_task[field] = task[field]
    return new_task

# Beispiel für Get ohne Parameter
@app.route('/todo/api/v1.0/tasks', methods=['GET'])
def get_tasks():
    return jsonify({'tasks': [make_public_task(task) for task in tasks]})

# Beispiel für GET by ID
@app.route('/todo/api/v1.0/tasks/<int:task_id>', methods=['GET'])
def get_task(task_id):
    task = [task for task in tasks if task['id'] == task_id]
    if len(task) == 0:
        abort(404)
    return jsonify({'task': [make_public_task(task[0])]})

# Beispiel für POST
@app.route('/todo/api/v1.0/tasks', methods=['POST'])
def create_task():
    if not request.json or not 'title' in request.json:
        abort(400)
    task = {
        'id': tasks[-1]['id'] + 1,
        'title': request.json['title'],
        'description': request.json.get('description', ""),
        'done': False
    }
    tasks.append(task)
    return jsonify({'task': task}), 201

# Beispiel für PUT
@app.route('/todo/api/v1.0/tasks/<int:task_id>', methods=['PUT'])
def update_task(task_id):
    task = [task for task in tasks if task['id'] == task_id]
    if len(task) == 0:
        abort(404)
    if not request.json:
        abort(400)
    if 'title' in request.json and type(request.json['title']) != unicode:
        abort(400)
    if 'description' in request.json and type(request.json['description']) is not unicode:
        abort(400)
    if 'done' in request.json and type(request.json['done']) is not bool:
        abort(400)
    task[0]['title'] = request.json.get('title', task[0]['title'])
    task[0]['description'] = request.json.get('description', task[0]['description'])
    task[0]['done'] = request.json.get('done', task[0]['done'])
    return jsonify({'task': task[0]})

# Beispiel für DELETE
@app.route('/todo/api/v1.0/tasks/<int:task_id>', methods=['DELETE'])
def delete_task(task_id):
    task = [task for task in tasks if task['id'] == task_id]
    if len(task) == 0:
        abort(404)
    tasks.remove(task[0])
    return jsonify({'result': True})


# Generierung von neuen Zertifikaten auf Basis der Userdaten von der RA
@app.route('/ca/cert/generate', methods=['POST'])
def generate_cert():
    # Abort, wenn kein JSON-Format oder ein Datenfeld fehlt
    if not request.json or not 'C' in request.json or not 'ST' in request.json or not 'L' in request.json or not 'O' in request.json or not 'OU' in request.json or not 'CN' in request.json:
        abort(400)
    # Erstellung vom Datensatz, noch in Form eines Tasks (muss noch geändert werden)
    task = {
        'C': request.json['C'],
        'ST': request.json['ST'],
        'L': request.json['L'],
        'O': request.json['O'],
        'OU': request.json['OU'],
        'CN': request.json['CN']
    }
    # Task anhängen, hier sollte konkrete Zertifikatsgenerierung aufgerufen werden
    tasks.append(task)
    # Rückmeldung an Client
    return jsonify({'task': task}), 201


if __name__ == '__main__':
    app.run(debug=True)