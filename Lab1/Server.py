import socketio
import eventlet

# Create a Socket.IO server
sio = socketio.Server()
# Wrap it in a WSGI app to handle HTTP/WebSocket routing
app = socketio.WSGIApp(sio)

@sio.event
def connect(sid, environ):
    print(f"[CONNECT] Client {sid} connected.")
    # Initialize an empty session state for this specific client
    sio.save_session(sid, {'username': None})

@sio.event
def disconnect(sid):
    print(f"[DISCONNECT] Client {sid} disconnected.")

@sio.event
def hello(sid, content):
    if not content:
        return "ERROR|Username required"
    
    # Save the username to this client's unique session
    sio.save_session(sid, {'username': content})
    print(f"[STATE] {sid} set username to: {content}")
    
    return f"OK|Hello {content}"

@sio.event
def msg(sid, content):
    # Retrieve the state for whoever sent this message
    session = sio.get_session(sid)
    username = session.get('username')

    if username is None:
        return "ERROR|HELLO required first"
    
    if not content:
        return "ERROR|Message cannot be empty"
        
    if len(content) > 200:
        return "ERROR|Message too long"

    print(f"[{username}] says: {content}")
    return f"OK|Message received from {username}"

@sio.event
def exit_server(sid):
    # We rename this to exit_server because 'exit' is a built-in Python command
    sio.disconnect(sid)
    return "OK|Goodbye"

if __name__ == '__main__':
    print("Socket.IO Server is running on port 12345...")
    # Eventlet is a highly scalable networking library that serves the WSGI app
    eventlet.wsgi.server(eventlet.listen(('127.0.0.1', 12345)), app)