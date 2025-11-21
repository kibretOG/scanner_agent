from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/scan-targets', methods=['POST'])
def scan_targets():
    targets = request.get_json()
    
    analyzed_targets = []
    for target in targets:
        analysis = {}
        
        # Rule 1: Check for excessive permissions
        permissions = target.get('permissions', {})
        clearance = target.get('clearance_level', '')
        if (clearance == 'LOW' or clearance == 'MEDIUM') and (permissions.get('admin') or permissions.get('emergency_override')):
            analysis['excessive_permissions'] = 'User has admin or emergency override permissions with a non-critical clearance level.'
            
        # Rule 2: Check for unusual access systems for field ops
        department = target.get('department', '')
        access_systems = target.get('access_systems', [])
        if department == 'Field Operations' and any('Database' in s for s in access_systems):
            analysis['unusual_access'] = 'Field Operations user has access to database systems.'

        # Add the analysis to the target object
        target['agent_analysis'] = analysis
        analyzed_targets.append(target)
        
    return jsonify(analyzed_targets)

if __name__ == '__main__':
    app.run(port=5002)
