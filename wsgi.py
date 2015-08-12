from tera import app as application

if __name__ == "__main__":
    context = ('ssl.crt', 'ssl.key')
    application.run(host='0.0.0.0', port='8080',
                    debug=True, ssl_context=context, threaded=True)
