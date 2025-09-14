import os
from flask import Flask, request, render_template

# Create the Flask application instance
app = Flask(__name__)

# Configure a folder to temporarily save uploaded files
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# This is the homepage route that handles both displaying the form and processing the upload
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # Check if the 'file' part is in the request
        if 'file' not in request.files:
            return 'No file part'
        file = request.files['file']
        
        # If the user does not select a file, the browser submits an empty part without a filename.
        if file.filename == '':
            return 'No selected file'
        
        # If a file is selected and has a name, save it
        if file:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(file_path)
            
            # For now, we'll just confirm the upload. 
            # In later steps, we will process this file.
            return f'File "{file.filename}" uploaded successfully to "{file_path}"'
    
    # This renders the index.html page for GET requests
    return render_template('index.html')

# This is how you run the application
if __name__ == '__main__':
    # debug=True allows the server to automatically reload when you make changes
    app.run(debug=True)
