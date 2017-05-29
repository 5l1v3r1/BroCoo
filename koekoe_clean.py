"""
Version         :       1.0.0
Developed by    :       Davy Boekhout
GitHub		:	https://github.com/dboekhout/BroCoo

Automating file extraction and analysis with
Cuckoo Sandbox, the Bro Network Security Monitor and Security Onion.

"""

import os
import requests
from pymongo import MongoClient
import datetime

# Absolute path to the Cuckoo binaries
cuckoo_dir_binaries = "CHANGE_THIS"

# API address of the Cuckoo instance so we can call delete via the REST API
api_address = "http://IP_ADDRESS_CUCKOO_API:PORT"

# REST API Delete call
delete_link = "/tasks/delete/"

# Setting up Mongodb connection
client = MongoClient()

# Connecting to the Cuckoo database
db = client.cuckoo

# Selecting the table "analysis"
collection = db.analysis

# Searching through all the entries in the analysis table
cur = collection.find()

# Determine the date of today
today = datetime.datetime.now()

# Age threshold for how long the analyses should be kept (Default = 14 days).
age_threshold = datetime.timedelta(days=14)


# Gathering old analysis jobs and putting them in the aforementioned list
def get_old_jobs():
    ids_old_analysis = collection.find(
        {"$and": [{"info.score": {"$lt": 1.0}}, {"info.ended": {"$lte": today - age_threshold}}]}).distinct('info.id')
    return ids_old_analysis


# Looping through the list and calling the REST API to delete the analyses
def delete_old_jobs(jobs_to_delete):
    deleted_jobs = []
    for analysis in jobs_to_delete:
        requests.get(api_address + delete_link + str(analysis))
        deleted_jobs.append(analysis)
    return deleted_jobs


# Deleting the old binaries from the Cuckoo binaries directory
def delete_old_binaries(job_binaries_to_delete):
    for subdir, dirs, files in os.walk(cuckoo_dir_binaries, followlinks=True):
        for job in job_binaries_to_delete:
            if subdir.endswith(str(job)):
                for sub_dir, directories, sub_files in os.walk(subdir):
                    if 'binary' in sub_files:
                        try:
                            os.remove(os.path.realpath(os.path.join(cuckoo_dir_binaries, sub_dir, 'binary')))
                        except OSError:
                            continue

# [Start of script]
if __name__ == '__main__':
    old_jobs = get_old_jobs()
    delete_old_binaries(old_jobs)
    successfully_deleted = delete_old_jobs(old_jobs)
    for successful_job in successfully_deleted:
        collection.delete_one({'info.id': successful_job})

