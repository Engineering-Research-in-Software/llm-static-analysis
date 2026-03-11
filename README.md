# LLM Powered Hybrid Android Application Static Analyzer

## The current state of this project is only a very limited POC

## How to run

1. Analyze an APK containing a WebView using the iWanDroid tool
2. Extract the resulting sqlite file and put it in `src/data`
3. Go into `src` and activate the python virtual environment
4. Run `pip install -r requirements.txt`
5. Create a `.env` file on the root of `analyzer` module, outside `src`
6. In that file, input the following environment variable `GEMINI_API_KEY=<your-api-key>`
7. On the root of the analyzer project, run `python src/main.py`
8. After a bit a resulting markdown file will be outputed to `reports`
9. Have fun improving it :)
