import json

# Structure reference
#
# [{}]



if __name__ == "__main__":
    with open("callsite_results.json", "r") as f:
        data = json.load(f)


    len = len(data)
    perPerson = len // 4
    
    for i in range(4):
        with open(f"callsite_results_{i}.json", "w") as f:
            json.dump(data[i*perPerson:(i+1)*perPerson], f, indent=4)