import json
import csv
import pandas as pd
from datetime import datetime
import urllib.parse

def extract_tech_stack(response_headers):
    """Extract technology stack from response headers"""
    tech_info = []
    tech_headers = [
        'x-powered-by', 'server', 'x-aspnet-version', 'x-generator', 
        'x-runtime', 'x-version', 'x-aspnetmvc-version', 'x-framework',
        'x-drupal-cache', 'x-wordpress', 'x-pingback'
    ]
    
    for header in response_headers:
        header_name = header['name'].lower()
        if header_name in tech_headers:
            tech_info.append(f"{header['name']}: {header['value']}")
    
    return '; '.join(tech_info) if tech_info else 'Unknown'

def get_header_value(headers, header_name):
    """Find specific header value"""
    for header in headers:
        if header['name'].lower() == header_name.lower():
            return header['value']
    return None

def extract_domain(url):
    """Extract domain from URL"""
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc
    except:
        return 'Unknown'

def get_file_extension(url):
    """Extract file extension from URL"""
    try:
        path = urllib.parse.urlparse(url).path
        if '.' in path:
            return path.split('.')[-1].lower()
        return 'html'  # Default for pages without extension
    except:
        return 'unknown'

def categorize_request(url, content_type):
    """Categorize request type"""
    file_ext = get_file_extension(url)
    
    if content_type:
        content_type = content_type.lower()
        if 'image' in content_type:
            return 'Image'
        elif 'javascript' in content_type or 'js' in content_type:
            return 'JavaScript'
        elif 'css' in content_type:
            return 'CSS'
        elif 'json' in content_type:
            return 'API/JSON'
        elif 'xml' in content_type:
            return 'XML'
        elif 'html' in content_type:
            return 'HTML'
        elif 'font' in content_type:
            return 'Font'
        elif 'video' in content_type:
            return 'Video'
        elif 'audio' in content_type:
            return 'Audio'
    
    # Categorize based on file extension
    if file_ext in ['jpg', 'jpeg', 'png', 'gif', 'svg', 'webp', 'ico']:
        return 'Image'
    elif file_ext in ['js']:
        return 'JavaScript'
    elif file_ext in ['css']:
        return 'CSS'
    elif file_ext in ['json']:
        return 'API/JSON'
    elif file_ext in ['xml']:
        return 'XML'
    elif file_ext in ['html', 'htm']:
        return 'HTML'
    elif file_ext in ['woff', 'woff2', 'ttf', 'eot']:
        return 'Font'
    elif file_ext in ['mp4', 'avi', 'mov', 'webm']:
        return 'Video'
    elif file_ext in ['mp3', 'wav', 'ogg']:
        return 'Audio'
    else:
        return 'Other'

def har_to_csv_complete(har_file_path, csv_file_path=None):
    """Complete conversion from HAR to CSV with all useful information"""
    
    # Set CSV filename if not specified
    if csv_file_path is None:
        csv_file_path = har_file_path.replace('.har', '_complete.csv')
    
    print(f"Reading file: {har_file_path}")
    
    # Read HAR file
    try:
        with open(har_file_path, 'r', encoding='utf-8') as f:
            har_data = json.load(f)
    except Exception as e:
        print(f"Error reading file: {e}")
        return None
    
    entries = har_data['log']['entries']
    print(f"Found {len(entries)} requests")
    
    # Create data list
    data = []
    
    for i, entry in enumerate(entries):
        try:
            request = entry['request']
            response = entry['response']
            
            # Basic information
            url = request['url']
            domain = extract_domain(url)
            content_type = get_header_value(response['headers'], 'content-type')
            
            row = {
                # Basic request information
                'Request_ID': i + 1,
                'URL': url,
                'Domain': domain,
                'Method': request['method'],
                'Status_Code': response['status'],
                'Status_Text': response['statusText'],
                
                # Timing information
                'Started_DateTime': entry['startedDateTime'],
                'Total_Time_ms': round(entry['time'], 2),
                'DNS_Time_ms': round(entry['timings'].get('dns', 0), 2),
                'Connect_Time_ms': round(entry['timings'].get('connect', 0), 2),
                'SSL_Time_ms': round(entry['timings'].get('ssl', 0), 2),
                'Send_Time_ms': round(entry['timings'].get('send', 0), 2),
                'Wait_Time_ms': round(entry['timings'].get('wait', 0), 2),
                'Receive_Time_ms': round(entry['timings'].get('receive', 0), 2),
                
                # Size information
                'Request_Size_bytes': request.get('bodySize', 0),
                'Response_Size_bytes': response.get('bodySize', 0),
                'Response_Headers_Size_bytes': response.get('headersSize', 0),
                'Total_Response_Size_bytes': response.get('bodySize', 0) + response.get('headersSize', 0),
                
                # Content information
                'Content_Type': content_type or 'Unknown',
                'Request_Category': categorize_request(url, content_type),
                'File_Extension': get_file_extension(url),
                
                # Technical information
                'Technology_Stack': extract_tech_stack(response['headers']),
                'HTTP_Version': response.get('httpVersion', 'Unknown'),
                'Cache_Control': get_header_value(response['headers'], 'cache-control'),
                'Content_Encoding': get_header_value(response['headers'], 'content-encoding'),
                'Content_Length': get_header_value(response['headers'], 'content-length'),
                
                # Security information
                'HTTPS': 'Yes' if url.startswith('https://') else 'No',
                'Security_Headers': [],
                
                # Additional information
                'Redirect_URL': response.get('redirectURL', ''),
                'Error_Message': response.get('statusText', '') if response['status'] >= 400 else '',
                'Query_String': urllib.parse.urlparse(url).query,
                'Has_Query_Params': 'Yes' if urllib.parse.urlparse(url).query else 'No',
            }
            
            # Check Security Headers
            security_headers = []
            security_header_names = [
                'strict-transport-security', 'content-security-policy', 
                'x-frame-options', 'x-content-type-options', 'x-xss-protection'
            ]
            
            for header in response['headers']:
                if header['name'].lower() in security_header_names:
                    security_headers.append(header['name'])
            
            row['Security_Headers'] = '; '.join(security_headers) if security_headers else 'None'
            row['Has_Security_Headers'] = 'Yes' if security_headers else 'No'
            
            # Cookie information
            cookies = request.get('cookies', [])
            row['Request_Cookies_Count'] = len(cookies)
            row['Has_Cookies'] = 'Yes' if cookies else 'No'
            
            # Post Data information
            post_data = request.get('postData', {})
            row['Has_Post_Data'] = 'Yes' if post_data else 'No'
            row['Post_Data_Size'] = len(post_data.get('text', '')) if post_data else 0
            
            data.append(row)
            
        except Exception as e:
            print(f"Error processing request {i + 1}: {e}")
            continue
    
    # Convert to DataFrame
    df = pd.DataFrame(data)
    
    # Order columns logically
    column_order = [
        'Request_ID', 'URL', 'Domain', 'Method', 'Status_Code', 'Status_Text',
        'Request_Category', 'Content_Type', 'File_Extension', 'HTTPS',
        'Total_Time_ms', 'DNS_Time_ms', 'Connect_Time_ms', 'SSL_Time_ms', 
        'Send_Time_ms', 'Wait_Time_ms', 'Receive_Time_ms',
        'Request_Size_bytes', 'Response_Size_bytes', 'Total_Response_Size_bytes',
        'Technology_Stack', 'HTTP_Version', 'Cache_Control', 'Content_Encoding',
        'Security_Headers', 'Has_Security_Headers', 'Has_Cookies', 'Request_Cookies_Count',
        'Has_Post_Data', 'Post_Data_Size', 'Has_Query_Params',
        'Started_DateTime', 'Redirect_URL', 'Error_Message'
    ]
    
    # Reorder columns (only existing ones)
    available_columns = [col for col in column_order if col in df.columns]
    df = df[available_columns]
    
    # Save as CSV
    df.to_csv(csv_file_path, index=False, encoding='utf-8')
    
    print(f"\nSuccess! Data saved to: {csv_file_path}")
    print(f"Total requests processed: {len(df)}")
    
    # Show quick statistics
    print("\nQuick Statistics:")
    print(f"• Domains: {df['Domain'].nunique()}")
    print(f"• Request methods: {df['Method'].value_counts().to_dict()}")
    print(f"• Status codes: {df['Status_Code'].value_counts().head().to_dict()}")
    print(f"• Content categories: {df['Request_Category'].value_counts().head().to_dict()}")
    
    # Show first 5 rows
    print(f"\nSample data:")
    print(df[['URL', 'Method', 'Status_Code', 'Request_Category', 'Total_Time_ms']].head())
    
    return df

# Usage example
if __name__ == "__main__":
    # Specify file name
    har_file = 'harfile.har'  # Put your file name here
    
    # Convert file
    df = har_to_csv_complete(har_file)
    
    if df is not None:
        print(f"\nCompleted successfully!")
        print(f"Data size: {df.shape[0]} rows × {df.shape[1]} columns")
        
        # Show all column names
        print(f"\nAvailable columns:")
        for i, col in enumerate(df.columns, 1):
            print(f"{i:2d}. {col}")


df = har_to_csv_complete('harfile.har')