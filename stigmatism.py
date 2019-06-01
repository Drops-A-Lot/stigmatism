#!/usr/bin/env python

"""
================================ Program/Module ================================
Name:        STIGmatism
Version:     0.1b
Description: Modifies DISA STIG checklists based on inputted search criteria.

Author(s):   Owen Cosby
Created:     21 May 2019
Modified:    01 Jun 2019
================================================================================

"""



"""
=================================== License ====================================
Copyright 2019, Owen Cosby <ocosby3 at gmail dot com>

Permission to use, copy, modify, and/or distribute this software for any purpose
with or without fee is hereby granted, provided that the above copyright notice
and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
THIS SOFTWARE.
================================================================================

"""



# Imports
import sys
import argparse
import xml.etree.ElementTree as ET



### Get Functions for Vulnerabilities ###
def getAllVulns(root):
    """
    ================================================================================
    Name:
        getAllVulns

    Description:
        Gets all VULN vulnerability elements from a root element.

    Parameter(s):
        root:   The root element node from where to begin searching.

    Returns:
        The findings from the 'root.findall' function for VULNs.

    Notes:
        N/A
    ================================================================================

    """
    return (root.findall(".//VULN"))



def getVuln(root, vuln_id):
    """
    ================================================================================
    Name:
        getVuln

    Description:
        Returns a VULN element with the specified vulnerability ID.

    Parameter(s):
        root:       The root element node from where to begin searching.
        vuln_id:    The vulnerability ID (i.e. 'V-123456') to find.

    Returns:
        The first VULN that matches the specified vulnerability ID (should only
        be one item).

    Notes:
        N/A
    ================================================================================

    """
    return root.find(".//STIG_DATA/[ATTRIBUTE_DATA='" + vuln_id + "'].." )



def getVulnElementValue(vuln, element):
    """
    ================================================================================
    Name:
        getVulnElementValue

    Description:
        Acquires the value from a specified element from with a VULN element.

    Parameter(s):
        vuln:       The vuln element to search.
        element:    The text name of the element to find.

    Returns:
        The value (if any) from the specified element name from the specified
        VULN element. If no elements are matched, then an empty string is returned.

    Notes:
        N/A
    ================================================================================

    """
    retval = vuln.find(element).text
    if type(retval) != str: retval = ""
    return retval



def getVulnID(vuln):
    """
    ================================================================================
    Name:
        getVulnID

    Description:
        Returns the vulnerability ID (i.e. 'V-123456') from a specified VULN
        element.

    Parameter(s):
        vuln:   The VULN element to be searched.

    Returns:
        The vulnerability ID for the given VULN, or an empty string if it cannot be
        found.

    Notes:
        Due to the way that the vulnerability ID is encoded for a vulnerability,
        the 'getVulnElementValue' function cannot be easily used to acquire this
        value. As such, this is a separate function that does not rely on the
        'getVulnElementValue' function.
    ================================================================================

    """
    vuln_id = vuln.find(".//STIG_DATA/[VULN_ATTRIBUTE='Vuln_Num']").find("ATTRIBUTE_DATA").text
    if type(vuln_id) != str: vuln_id = ""
    return vuln_id



def getVulnStatus(vuln):
    """
    ================================================================================
    Name:
        getVulnStatus

    Description:
        Returns the status (i.e. 'Not_Reviewed', 'Open', 'NotAFinding') of a
        specified VULN.

    Parameter(s):
        vuln:   The VULN element to be searched.

    Returns:
        The status of the given VULN.

    Notes:
        N/A
    ================================================================================

    """
    status = getVulnElementValue(vuln, "STATUS")
    return status



def getVulnFindingDetails(vuln):
    """
    ================================================================================
    Name:
        getVulnFindingDetails

    Description:
        Acquired the value of the 'FINDING_DETAILS' section of a VULN.

    Parameter(s):
        vuln:   The VULN element to be searched.

    Returns:
        The finding details from the given VULN.

    Notes:
        N/A
    ================================================================================

    """
    finding_details = getVulnElementValue(vuln, "FINDING_DETAILS")
    return finding_details



def getVulnComments(vuln):
    """
    ================================================================================
    Name:
        getVulnComments

    Description:
        Acquired the value of the 'COMMENTS' section of a VULN.

    Parameter(s):
        vuln:   The VULN element to be searched.

    Returns:
        The comments from the given VULN.

    Notes:
        N/A
    ================================================================================

    """
    comments = getVulnElementValue(vuln, "COMMENTS")
    return comments




### Set functions for vulnerabilities ###
def setVulnElementValue(vuln, element, value):
    """
    ================================================================================
    Name:
        setVulnElementValue

    Description:
        Sets the value for a specified element in a given VULN.

    Parameter(s):
        vuln:       The VULN element to be searched.
        element:    The text name of the element to find.
        value:      The value to which the element should be set.

    Returns:
        N/A

    Notes:
        N/A
    ================================================================================

    """
    vuln.find(element).text = value
    return



def setVulnStatus(vuln, status):
    """
    ================================================================================
    Name:
        setVulnStatus

    Description:
        Sets the status (i.e. 'Not_Reviewed', 'Open', 'NotAFinding') of a given
        VULN.

    Parameter(s):
        vuln:   The VULN element to be searched.
        status: The new status (i.e. 'Not_Reviewed', 'Open', 'NotAFinding').

    Returns:
        N/A

    Notes:
        N/A
    ================================================================================

    """
    setVulnElementValue(vuln, "STATUS", value)
    return



def setVulnFindingDetails(vuln, finding_details):
    """
    ================================================================================
    Name:
        setVulnFindingDetails

    Description:
        Sets the finding details for a given VULN.

    Parameter(s):
        vuln:               The VULN element to be searched.
        finding_details:    The new text for the finding details.

    Returns:
        N/A

    Notes:
        N/A
    ================================================================================

    """
    setVulnElementValue(vuln, "FINDING_DETAILS", finding_details)
    return


def setVulnComments(vuln, comments):
    """
    ================================================================================
    Name:
        setVulnComments

    Description:
        Sets the comments for a given VULN.

    Parameter(s):
        vuln:        The VULN element to be searched.
        comments:    The new text for the comments.

    Returns:
        N/A

    Notes:
        N/A
    ================================================================================

    """
    setVulnElementValue(vuln, "COMMENTS", comments)
    return



### Match functions for vulnerabilities ###
def matchVuln(vuln, element, criteria):
    """
    ================================================================================
    Name:
        matchVuln

    Description:
        Sets the finding details of a given VULN.

    Parameter(s):
        vuln:       The VULN element to be searched.
        element:    The element to find.
        criteria:   The search criteria against which to match.
    Returns:
        True:   If a match is found.
        False:  If a match is not found.

    Notes:
        N/A
    ================================================================================

    """
    if (getVulnElementValue(vuln, element) == criteria): return True
    return False



def matchVulnsToCriteria(vulns, match_criteria):
    """
    ================================================================================
    Name:
        matchVulnsToCriteria

    Description:
        Matches a list of VULN items against a dictionary of criteria.

    Parameter(s):
        vuln:               The VULN element to be searched.
        match_criteria:     A dictionary of criteria to use for matching.
                            The dictionary should be in the format of
                            'ELEMENT:VALUE' (i.e. '{"STATUS": "Open"}').

    Returns:
        A list of VULN elements which match the match criteria.

    Notes:
        N/A
    ================================================================================

    """
    matches = []
    for vuln in vulns:
        doesMatch = False
        for elem in match_criteria:
            doesMatch = matchVuln(vuln, elem, match_criteria[elem])
            if (doesMatch == False): break
        if doesMatch:
            matches.append(vuln)
    return matches



def modifyVulnsWithCriteria(vulns, change_criteria):
    """
    ================================================================================
    Name:
        modifyVulnsWithCriteria

    Description:
        Modifies a list of VULN elements using the changes specified.

    Parameter(s):
        vulns:              A list of VULN elements to be changed.
        change_criteria:    A dictionary of criteria to use for making changes to
                            the specified list of VULN elements (vulns).
                            The dictionary should be in the format of
                            'ELEMENT:VALUE' (i.e. '{"STATUS": "Open"}').

    Returns:
        N/A

    Notes:
        N/A
    ================================================================================

"""
    for vuln in vulns:
        for exc in change_criteria:
            setVulnElementValue(vuln, exc, change_criteria[exc])
    return




def main(argc, argv):
    """
    ============================================================================
    Name:
        main

    Description:
        The main program function.

    Parameter(s):
        argc: The number of arguments passed on invocation.
        argv: A list (tuple) of all supplied arguments.

    Returns:
        0 for success.
        1 for error/failure.

    Notes:
    ============================================================================

    """

    # Configure the argument parser for this program's arguments
    parser = argparse.ArgumentParser(description='Perform expression matched searches/modifications on/to DISA STIG checklists.')
    parser.add_argument('-m',    '--match',    metavar='EXPRESSION', type=str,                action='append',                help="An expression to use as search criteria for <VULN> elements. Multiple expressions can be added by repating this option.")
    parser.add_argument('-c',    '--change',   metavar='EXPRESSION', type=str,                action='append',                help="An expression to execute upon a successful match of any <VULN> elements. Multiple expressions can be added by repeating this option.")
    parser.add_argument('-f',    '--file',     metavar='FILENAME',   type=str,                                 required=True, help="The full path to the file that is to be searched/modified.")
    parser.add_argument('-w',    '--write',                                                   action='store_true',            help="Write any changes to the input file. By default, all ouptut will be to STDOUT. (WARNING: Will overwrite input file with new/updated data)")
    parser.add_argument('-s',    '--simulate',                                                action='store_true',            help="Run as a simulation. Will not write to a file.")

    # Display the full help list if no options are specified
    if argc == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    # Process command-line arguments
    args = parser.parse_args()


    # Set initial variables
    checklist_filename = args.file
    tree    = ET.parse(checklist_filename)
    root    = tree.getroot()

    # Will hold a list of all vulnerability (VULN) elements from the checklist
    vulns = None

    # A list of vulnerability elements that match the provided match criteria
    matches = []

    # The criteria which must be matched in the checklist
    match_criteria = {}

    # The criteria by which the checklist will be changed
    change_criteria  = {}



    # Iterate through the 'match' arguments and add them to the 'match_criteria'
    # dictionary
    if args.match != None:
        for match in args.match:
            stripped_match = [x.strip() for x in match.split('=')]
            match_criteria.update([stripped_match])


    # Iterate through the 'exc' arguments and add them to the 'change_criteria'
    # dictionary
    if args.change != None:
        for change in args.change:
            stripped_change = [x.strip() for x in change.split('=')]
            change_criteria.update([stripped_change])


    # Get and store all of the VULN elements from the checklist
    vulns = getAllVulns(root)

    # Find any/all VULNs which match the specified match criteria
    matches = matchVulnsToCriteria(vulns, match_criteria)

    # Modify all of the matches using the change criteria
    modifyVulnsWithCriteria(matches, change_criteria)

    # If not using simulation, and the input file is to be overwritten, then do
    # so
    if ((not args.simulate) and args.write):
        tree.write(checklist_filename)
    # If this is a simulation, or if the input file is NOT being overwritten,
    # then dump the new checklist output to the console (STDOUT)
    else:
        ET.dump(root)

    return 0



# If invoked as script, then execute the 'main' function
if __name__ == "__main__":
    sys.exit(main(len(sys.argv), sys.argv))



# Template header for functions/classes
"""
================================================================================
Name:
    N/A

Description:
    N/A

Parameter(s):
    N/A

Returns:
    N/A

Notes:
    N/A
================================================================================

"""
