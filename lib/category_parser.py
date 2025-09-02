"""
Functions defined in this file parse CSV files with APP and URL categories
to retrieve information about what categories should be managed,
what categories should be allowed for all users, and what categories should be blocked outright.
"""

import os.path
import csv

import settings


def parse_app_categories(filename):
    """
    Reads App categories from the input CSV file and builds a list of dictionaries with metadata.

    Each element of the dictionary is a key that equals the column name,
    and a value that is a string in the cell.

    Args:
        filename (str): Path to the CSV file containing app categories data.

    Returns:
        list: List of dictionaries containing app categories metadata (1 dictionary per category).
            Returns None if the file is not found.
    """

    if os.path.exists(filename):
        print(f"App categories metadata file found - parsing data...", end='')
        # reading the file into a list of dictionaries
        categories = list()
        with open(filename, mode='r') as csv_file:
            csv_reader = csv.DictReader(csv_file)
            for row in csv_reader:
                categories.append(row)
        print(f'{len(categories)} categories found.')
    else:
        print(f"App categories metadata file is not found")
        categories = None

    return categories


def parse_url_categories(filename):
    """
    Reads URL categories from the input CSV file and builds a list of dictionaries with metadata.

    Each element of the dictionary is a key that equals the column name,
    and a value that is a string in the cell.

    Args:
        filename (str): Path to the CSV file containing URL categories data.

    Returns:
        list: List of dictionaries containing URL categories metadata (1 dictionary per category).
            Returns None if the file is not found.
    """
    if os.path.exists(filename):
        print(f"URL categories metadata file found - parsing data...", end='')
        # reading the file into a list of dictionaries

        categories = list()
        with open(filename, mode='r') as csv_file:
            csv_reader = csv.DictReader(csv_file)
            for row in csv_reader:
                categories.append(row)
        print(f'{len(categories)} categories found.')
    else:
        print(f"URL categories metadata file is not found")
        categories = None

    return categories
