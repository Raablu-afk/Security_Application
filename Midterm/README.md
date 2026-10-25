## Setup
pip install -r requirements.txt
python create_user.py alice analyst
python create_user.py admin admin

## Run (three terminals)
python test_website.py     # http://127.0.0.1:8765
python server.py           # 127.0.0.1:5050
python client.py


## Tests
python run_tests.py > docs/test_output.txt