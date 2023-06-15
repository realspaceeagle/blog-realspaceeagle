#!/bin/bash

# Define the search and replace strings
search_str="\!\[\["
replace_str="![image](/post_img/halosec/post1/"
closing_str="\]\]"
closing_replace_str=")"

# Find all Markdown files in the current directory and its subdirectories
find . -type f -name "*.md" | while IFS= read -r file; do
    # Replace occurrences of ![[ with ![image](/post_img/halosec/post1/ 
    sed -i -e "s|$search_str|$replace_str|g" "$file"

    # Replace occurrences of ]] with )
    sed -i -e "s|$closing_str|$closing_replace_str|g" "$file"
done

echo "Replacement completed successfully."