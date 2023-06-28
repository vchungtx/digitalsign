package com.digitalsign.signbackend.database.entity;

import javax.persistence.*;
import java.util.Date;


@Entity
@Table(name = "transaction", schema = "digital_sign", catalog = "")
public class TransactionEntity {
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Id
    @Column(name = "transaction_id", nullable = false)
    private long transactionId;
    @Basic
    @Column(name = "file_type", nullable = true, length = 30)
    private String fileType;
    @Basic
    @Column(name = "source_file", nullable = true, length = 500)
    private String sourceFile;
    @Basic
    @Column(name = "temp_file", nullable = true, length = 500)
    private String tempFile;
    @Basic
    @Column(name = "signed_file", nullable = true, length = 500)
    private String signedFile;
    @Basic
    @Column(name = "data", nullable = true, length = -1)
    private String data;
    @Basic
    @Column(name = "created_date", nullable = true)
    private Date createdDate;
    @Basic
    @Column(name = "updated_date", nullable = true)
    private Date updatedDate;
    @Basic
    @Column(name = "certificate_chain", nullable = true, length = 4000)
    private String certificateChain;
    public long getTransactionId() {
        return transactionId;
    }

    public void setTransactionId(long transactionId) {
        this.transactionId = transactionId;
    }

    public String getFileType() {
        return fileType;
    }

    public void setFileType(String fileType) {
        this.fileType = fileType;
    }

    public String getSourceFile() {
        return sourceFile;
    }

    public void setSourceFile(String sourceFile) {
        this.sourceFile = sourceFile;
    }

    public String getTempFile() {
        return tempFile;
    }

    public void setTempFile(String tempFile) {
        this.tempFile = tempFile;
    }

    public String getSignedFile() {
        return signedFile;
    }

    public void setSignedFile(String signedFile) {
        this.signedFile = signedFile;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public Date getCreatedDate() {
        return createdDate;
    }

    public void setCreatedDate(Date createdDate) {
        this.createdDate = createdDate;
    }

    public Date getUpdatedDate() {
        return updatedDate;
    }

    public void setUpdatedDate(Date updatedDate) {
        this.updatedDate = updatedDate;
    }

    public String getCertificateChain() {
        return certificateChain;
    }

    public void setCertificateChain(String certificateChain) {
        this.certificateChain = certificateChain;
    }
}
