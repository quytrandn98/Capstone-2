#!/bin/bash

#Get configuration details
CONFIGFILE=configuration
source $CONFIGFILE

TIME_FORMAT='%Y%m%d'
cTime=$(date +"${TIME_FORMAT}")
LOGFILENAME=$LOG_PATH/backup-${cTime}.log
CREDENTIALS="--defaults-extra-file=$MYSQL_CRE"

[ ! -d $LOG_PATH ] && ${MKDIR} -p ${LOG_PATH}
echo "" > ${LOGFILENAME}
echo "<<<<<<   Database Dump Report :: `date +%D`  >>>>>>" >> ${LOGFILENAME}
echo "" >> ${LOGFILENAME}
echo "DB Name  :: DB Size   Filename" >> ${LOGFILENAME}

#Check configuration file is existed
check_config(){
        [ ! -f $CONFIGFILE ] && close_on_error "Config file not found, make sure config file is correct"
}

mysql_backup(){
        FILEPATH="${LOCAL_BACKUP_DIR}/${cTime}/"
        if [ ! -d "${FILEPATH}" ]; then
                $MKDIR -p ${FILEPATH}
        fi
        #Prevent database is being written while perform backup 
        $MYSQL ${CREDENTIALS} -Ae"FLUSH TABLES WITH READ LOCK;"

        for database in "${DB_NAMES[@]}"
        do
        FILENAME="${database}_${cTime}.gz"
        BACKUPFILE="$FILEPATH$FILENAME"
        if [ ! -f "${BACKUPFILE}" ]; then   
                $SLEEP 5
                #Backup file then compress it
                $MYSQLDUMP ${CREDENTIALS} --single-transaction --host=$MYSQL_HOST --port=$MYSQL_PORT "$database" | ${GZIP} -9 > $BACKUPFILE

                #Write to log file
                echo "$database   :: `du -sh ${BACKUPFILE}`"  >> ${LOGFILENAME}
        fi
        #Enable database to be written in
        $MYSQL ${CREDENTIALS} -Ae"UNLOCK TABLES;"
done

}

close_on_error(){
        echo "$@"
        exit 99
}

check_commands(){
        # Check if executable is existed
        [ ! -x $GZIP ] && close_on_error "Executable $GZIP not found."
        [ ! -x $MYSQL ] && close_on_error "Executable $MYSQL not found."
        [ ! -x $MYSQLDUMP ] && close_on_error "Executable $MYSQLDUMP not found."
        [ ! -x $MKDIR ] && close_on_error "Executable $MKDIR not found."
        [ ! -x $GREP ] && close_on_error "Executable $GREP not found."
        [ ! -x $SLEEP ] && close_on_error "Executalbe $SLEEP not found."
        [ ! -x $FIND ] && close_on_error "Executable $FIND not found."
        [ ! -x $MYSQLADMIN ] && close_on_error "Executable $MYSQLADMIN not found."
        [ ! -x $SCP ] && close_on_error "Executable $SCP not found."
        [ ! -x $FIND ] && close_on_error "Executable $FIND not found."
        [ ! -x $SSH ] && close_on_error "Executable $SSH not found."
}

check_mysql_connection(){
        # Check if MySQL server is alive
        $MYSQLADMIN ${CREDENTIALS} --host=${MYSQL_HOST} --port=${MYSQL_PORT} ping | ${GREP} 'alive'>/dev/null
        [ $? -eq 0 ] || close_on_error "Cannot connect to MySQL Server. Make sure username and password setup correctly in $CONFIGFILE"
}

sftp_backup(){
        cd $FILEPATH
        ${SCP} -i ${IDENTITY_FILE} -P ${SFTP_PORT} "$BACKUPFILE" ${SFTP_USERNAME}@${SFTP_HOST}:${SFTP_UPLOAD_DIR}/
}

clean_backup(){
        #Delete backup file that is more than 30 days old
        $FIND "$FILEPATH" -type f -mtime +30 -delete
        $SSH -i ${IDENTITY_FILE} -p ${SFTP_PORT} ${SFTP_USERNAME}@${SFTP_HOST}  -t "$FIND ${FILEPATH} -type f -mtime +30 -delete"
}

#main
check_config
check_commands
check_mysql_connection
mysql_backup
sftp_backup
clean_backup