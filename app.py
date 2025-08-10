from flask import Flask, render_template, request
from coldbox_scanner import ColdBoxPenTester

app = Flask(__name__)
SAFE_TARGET = 'http://testphp.vulnweb.com'

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        scanner = ColdBoxPenTester(SAFE_TARGET)
        results = scanner.comprehensive_scan()
        report = scanner.generate_report(results)
        return render_template('results.html', report=report, target=SAFE_TARGET)
    return render_template('index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
