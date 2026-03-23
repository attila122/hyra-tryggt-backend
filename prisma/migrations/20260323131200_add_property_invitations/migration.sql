-- CreateEnum
CREATE TYPE "InvitationStatus" AS ENUM ('PENDING', 'ACCEPTED', 'EXPIRED');

-- CreateTable
CREATE TABLE "property_invitations" (
    "id" SERIAL NOT NULL,
    "email" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "status" "InvitationStatus" NOT NULL DEFAULT 'PENDING',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "propertyId" INTEGER NOT NULL,
    "invitedById" INTEGER NOT NULL,

    CONSTRAINT "property_invitations_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "property_invitations_token_key" ON "property_invitations"("token");

-- CreateIndex
CREATE INDEX "property_invitations_email_idx" ON "property_invitations"("email");

-- CreateIndex
CREATE INDEX "property_invitations_token_idx" ON "property_invitations"("token");

-- CreateIndex
CREATE INDEX "property_invitations_propertyId_idx" ON "property_invitations"("propertyId");

-- AddForeignKey
ALTER TABLE "property_invitations" ADD CONSTRAINT "property_invitations_propertyId_fkey" FOREIGN KEY ("propertyId") REFERENCES "properties"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "property_invitations" ADD CONSTRAINT "property_invitations_invitedById_fkey" FOREIGN KEY ("invitedById") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
