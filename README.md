# IPU-Installer

IPU Installer is an application developed by Johan Schrewelius to help with feature updates for Windows 10 where a task sequence might not be suitable. It also helps minimize the down-time for your end users since they can use the computer as the upgrade runs in the background.\
While this script is meant to make it easier to implement the solution, **please read the documentation!**\
It's important that you understand how the solution is supposed to work before running this script.\
Visit https://onevinn.schrewelius.it/ to find the documentation.


## What does the script do?
> #### The script will automatically:
>
> - Download the source files from https://onevinn.schrewelius.it/Files/IPUInstaller/IPUInstaller.zip 
> - Import IPU Installer app and Deployment Scheduler app to ConfigMgr
> - Deploy IPU Installer app and Deployment Scheduler app to the main IPU-collection
> - Create all the collections including the correct rules
> - Create a new Device Collection folder that will house the newly created collections
> - Create a new Client Policy with a more frequent schedule for Hardware Inventory. Set PS ExecutionPolicy to ByPass
> - Deploy the Client Policy to the newly created collections to be used with IPU Installer
> - Create and deploy a maintenance window to the main IPU-collection.
>   - _This might not be needed in your environment, in that case remember to delete it!_
> - Import ".\IPUInstaller\ConsoleScript\Reset_IPU_Status.ps1" script to the console
>

## Remember to check and modify the variables inside the script before running!

> #### Check the following variable segments in the script:
>
> - Variables for app creation
> - IPU App
> - Variables for collections and client setting
> - Deployment Scheduler App


## Current limitations:
The script will not update or import any .mof files, you will currently have to this manually.\
If you run the script before you edit and import the .mof files it will tell you that your environment doesn't meet the requirements yet.  
You will still get the apps but the collections won't be created. Please fix the hardware inventory classes according to the documentation and run the script again to successfully complete the installation.

## Planned features:
Maybe automatic handling of the .mof files...?
