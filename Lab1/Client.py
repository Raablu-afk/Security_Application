import socketio

# Create a Socket.IO client
sio = socketio.Client()

@sio.event
def connect():
    print("Connected to server")

@sio.event
def disconnect():
    print("Disconnected from server")

# Connect to the WSGI server URL
sio.connect('http://127.0.0.1:12345')

username = input("Enter your username: ")

# sio.call triggers the event on the server and waits for the 'return' value
response = sio.call('hello', username)
print("Server:", response)

while True:
    message = input("Enter message or type EXIT to leave: ")

    if message.upper() == "EXIT":
        response = sio.call('exit_server')
        print("Server:", response)
        sio.disconnect()
        break

    response = sio.call('msg', message)
    print("Server:", response)