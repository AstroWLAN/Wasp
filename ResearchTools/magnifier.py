# magnifier.py 
# Interactive .csv lookup tool - search for content in .csv files and return matches
# Author : Dario Crippa [ AstroWLAN ]

# IMPORTS
import os
import argparse
import duckdb

# Interactive .csv lookup function
def csv_lookup(csv_file):
    try:
        # Establish a connection to DuckDB
        print(f"\033[90mLoading .csv file: {csv_file}...\033[0m")
        conn = duckdb.connect()
        
        # Get the .csv info
        info_query = f"SELECT COUNT(*) as row_count FROM '{csv_file}'"
        row_count = conn.execute(info_query).fetchone()[0]
        
        # Get the column names
        columns_query = f"DESCRIBE SELECT * FROM '{csv_file}' LIMIT 1"
        columns = [row[0] for row in conn.execute(columns_query).fetchall()]
        
        # Visualize basic information about the .csv
        print(f"\033[1;92mDone\033[0m")
        print(f"\033[90mThere are {row_count} rows and {len(columns)} columns\033[0m")
        print(f"\033[90mHeader [ {', '.join(columns)} ]\n\033[0m")
        
        # Search loop
        while True:
            # User input
            search_content = input("\033[37mEnter content to search for [ \033[90m'quit' to exit\033[37m ] : \033[0m").strip()
            # EXIT
            if search_content.lower() in ['quit', 'exit', 'q']:
                print("\033[90mShutting down...\033[0m")
                break
            if not search_content:
                print("\033[1;93mWarning ⚠️\n\033[0;90mEnter some content to search for\n\033[0m")
                continue
            # Split the search content into multiple terms
            search_terms = search_content.split()
            # Build the SQL query for multi-term search
            where_conditions = []
            for term in search_terms:
                # Create the condition to search across all columns
                column_conditions = []
                for col in columns:
                    column_conditions.append(f"LOWER(CAST({col} AS VARCHAR)) LIKE '%{term.lower().replace("'", "''")}%'")
                where_conditions.append(f"({' OR '.join(column_conditions)})")
            
            where_clause = ' AND '.join(where_conditions)
            search_query = f"SELECT * FROM '{csv_file}' WHERE {where_clause} LIMIT 1"
            
            try:
                result = conn.execute(search_query).fetchone()
                
                if result:
                    print(f"\033[1;92mFound\033[0m")
                    print(f"\033[90mThe search terms are \033[1;37m{', '.join(search_terms)}\033[0m")
                    print(f"\033[0;90mFull row information\033[0m")
                    
                    # Show the full row in a readable format
                    for i, col in enumerate(columns):
                        print(f"\033[90m{col} \033[37m {result[i]}")
                    print()
                else:
                    print("\033[1;91mNot Found\033[0m\n\033[0;90mNo rows contain all the search terms\n\033[0m")
            # Exception Handling : log the error      
            except Exception as error:
                print(f"\033[1;91mError 🔥\n\033[0;90m{str(error)}\n\033[0m")
        # Close the connection to DuckDB
        conn.close()
    # Exception Handling : log the error           
    except FileNotFoundError:
        print(f"\033[1;91mError 🔥\n\033[0;90mFile not found: {csv_file}\n\033[0m")
    except Exception as error:
        print(f"\033[1;91mError 🔥\n\033[0;90m{str(error)}\n\033[0m")

# MAIN
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Interactive .csv lookup tool")
    parser.add_argument('-i', '--input', type=str, required=True, help='Input .csv file to search in')
    args = parser.parse_args()
    # Check if the input file exists
    if not os.path.isfile(args.input):
        print(f"\033[1;91mError 🔥\n\033[0;90mInput file does not exist: {args.input}\n\033[0m")
        exit(1)
    # Check if the input file has .csv extension
    if not args.input.lower().endswith('.csv'):
        print(f"\033[1;91mError 🔥\n\033[0;90mInput file must be a .csv file\n\033[0m")
        exit(1)
    print("\n\033[1;37mResearch Kit 🔍\n\033[0;90mA simple .csv search tool\n\033[0m")
    csv_lookup(args.input)